//! Interactive entry point (4c).
//!
//! When `bosphorus.exe` is launched from Explorer — no arguments, and this
//! process owns its console — there is no shell to type into. Instead of a
//! plain menu we take over the console with a tiny arrow-key TUI (raw VT
//! sequences + the Win32 Console API, no framework dependency) offering
//! "run once" and "install as a service", with a live language toggle.
//!
//! Both actions self-elevate through UAC (`ShellExecuteW "runas"`) when the
//! process is not already Administrator: "run once" re-spawns `--engine` in a
//! new window, "install"/"uninstall" re-spawns the matching `service` sub-
//! command with `--from-launcher` so it reports its result in a MessageBox.
//!
//! Running `bosphorus` with no arguments *from a shell* is unchanged: print
//! the CLI usage and exit 2.

use std::ffi::{c_void, OsString};
use std::io::Write;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Console::{
    GetConsoleMode, GetConsoleOutputCP, GetConsoleProcessList, GetStdHandle, ReadConsoleInputW,
    SetConsoleMode, SetConsoleOutputCP, CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    INPUT_RECORD, KEY_EVENT, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MESSAGEBOX_STYLE, SW_HIDE,
    SW_SHOWNORMAL,
};

use crate::i18n::{self, Msg};

/// Marker appended to an elevated re-spawn's argv so the `service` sub-command
/// pops a MessageBox with its result (the re-spawn's console is hidden).
pub const FROM_LAUNCHER_FLAG: &str = "--from-launcher";

// --------------------------------------------------------------------------- //
//  Pure decision layer (unit-tested)
// --------------------------------------------------------------------------- //

/// Which top-level screen the no-arguments entry point shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Started from a shell: print CLI usage and exit 2.
    Usage,
    /// Double-clicked: run the interactive menu.
    Tui,
}

/// The only routing input: did Explorer create our console (double-click) or
/// were we started from an existing shell?
pub fn decide(double_click: bool) -> Screen {
    if double_click {
        Screen::Tui
    } else {
        Screen::Usage
    }
}

/// A row in the menu. Split by how it's handled:
///   * "exit" rows end the menu and `run()` acts on them (possibly elevating);
///   * "inline" rows run inside the menu loop and return to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    // exit rows
    RunOnce,
    SelfTest,
    InstallService,
    UninstallService,
    Quit,
    // inline rows
    ShowStatus,
    CheckFilters,
    ProfileInfo,
    OpenDataFolder,
    About,
    ToggleLang,
}

impl MenuItem {
    /// Inline rows are handled without leaving the menu.
    fn is_inline(self) -> bool {
        matches!(
            self,
            MenuItem::ShowStatus
                | MenuItem::CheckFilters
                | MenuItem::ProfileInfo
                | MenuItem::OpenDataFolder
                | MenuItem::About
                | MenuItem::ToggleLang
        )
    }
}

/// What the user picked to leave the menu with. Inline rows (status,
/// check-filters, profile, folder, about, language) never produce one — they
/// run inside the menu loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherChoice {
    RunOnce,
    SelfTest,
    InstallService,
    UninstallService,
    Quit,
}

/// A concrete thing `run()` then does. Split from the choice so the
/// elevate-vs-do-here fork stays a pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedAction {
    RunEngineHere,
    ElevateAndRun,
    RunSelfTestHere,
    ElevateAndSelfTest,
    InstallHere,
    ElevateAndInstall,
    UninstallHere,
    ElevateAndUninstall,
    Exit,
}

/// The menu contents + cursor. `items_for` is the whole "installed vs not"
/// branch; keeping it a pure function is what makes it testable.
#[derive(Debug, Clone)]
pub struct MenuModel {
    pub items: Vec<MenuItem>,
    pub cursor: usize,
}

impl MenuModel {
    pub fn new(installed: bool) -> Self {
        Self { items: Self::items_for(installed), cursor: 0 }
    }

    pub fn items_for(installed: bool) -> Vec<MenuItem> {
        let mut v = vec![
            MenuItem::RunOnce,
            MenuItem::CheckFilters,
            MenuItem::SelfTest,
        ];
        if installed {
            v.push(MenuItem::ShowStatus);
            v.push(MenuItem::UninstallService);
        } else {
            v.push(MenuItem::InstallService);
        }
        v.push(MenuItem::ProfileInfo);
        v.push(MenuItem::OpenDataFolder);
        v.push(MenuItem::About);
        v.push(MenuItem::ToggleLang);
        v.push(MenuItem::Quit);
        v
    }

    pub fn up(&mut self) {
        let n = self.items.len();
        self.cursor = (self.cursor + n - 1) % n;
    }
    pub fn down(&mut self) {
        self.cursor = (self.cursor + 1) % self.items.len();
    }
    pub fn selected(&self) -> MenuItem {
        self.items[self.cursor]
    }
}

/// The elevate-vs-run-here fork. Every "install/uninstall/run" needs
/// Administrator; "show status" and "quit" do not.
pub fn dispatch_choice(choice: LauncherChoice, elevated: bool) -> ResolvedAction {
    use LauncherChoice as C;
    use ResolvedAction as R;
    match (choice, elevated) {
        (C::RunOnce, true) => R::RunEngineHere,
        (C::RunOnce, false) => R::ElevateAndRun,
        (C::SelfTest, true) => R::RunSelfTestHere,
        (C::SelfTest, false) => R::ElevateAndSelfTest,
        (C::InstallService, true) => R::InstallHere,
        (C::InstallService, false) => R::ElevateAndInstall,
        (C::UninstallService, true) => R::UninstallHere,
        (C::UninstallService, false) => R::ElevateAndUninstall,
        (C::Quit, _) => R::Exit,
    }
}

fn lang_code(l: i18n::Lang) -> &'static str {
    match l {
        i18n::Lang::En => "en",
        i18n::Lang::Tr => "tr",
    }
}

/// Elevated re-spawn argv for "install as a service".
pub fn elevated_install_args(lang: i18n::Lang) -> Vec<OsString> {
    vec![
        "service".into(),
        "install".into(),
        "--lang".into(),
        lang_code(lang).into(),
        FROM_LAUNCHER_FLAG.into(),
    ]
}

/// Elevated re-spawn argv for "uninstall the service".
pub fn elevated_uninstall_args(lang: i18n::Lang) -> Vec<OsString> {
    vec![
        "service".into(),
        "uninstall".into(),
        "--lang".into(),
        lang_code(lang).into(),
        FROM_LAUNCHER_FLAG.into(),
    ]
}

/// Elevated re-spawn argv for "run once" — straight into `--engine`, no
/// launcher marker (the engine path never shows a TUI).
pub fn elevated_run_args(lang: i18n::Lang) -> Vec<OsString> {
    vec!["--engine".into(), "--lang".into(), lang_code(lang).into()]
}

/// Elevated re-spawn argv for the WinDivert self-test.
pub fn elevated_selftest_args(lang: i18n::Lang) -> Vec<OsString> {
    vec!["--selftest".into(), "--lang".into(), lang_code(lang).into()]
}

// --------------------------------------------------------------------------- //
//  Entry point
// --------------------------------------------------------------------------- //

pub fn run() -> anyhow::Result<()> {
    match decide(is_double_click()) {
        Screen::Usage => {
            crate::usage();
            std::process::exit(2);
        }
        Screen::Tui => {}
    }

    let installed = crate::service::is_installed();
    let elevated = is_elevated();

    // NB: unlike 4b we do NOT FreeConsole() — the TUI lives in this console.
    match dispatch_choice(tui_menu(installed), elevated) {
        ResolvedAction::Exit => Ok(()),

        ResolvedAction::RunEngineHere => {
            let res = crate::engine_cmd::run_engine(crate::engine_cmd::EngineOpts::default());
            pause();
            res
        }
        ResolvedAction::ElevateAndRun => elevate(elevated_run_args(i18n::get()), false),

        ResolvedAction::RunSelfTestHere => {
            let res = crate::selftest::run_all();
            pause();
            res
        }
        ResolvedAction::ElevateAndSelfTest => elevate(elevated_selftest_args(i18n::get()), false),

        ResolvedAction::InstallHere => {
            let res = crate::service::install::install(&install_opts());
            show_install_result(&res);
            res
        }
        ResolvedAction::ElevateAndInstall => elevate(elevated_install_args(i18n::get()), true),

        ResolvedAction::UninstallHere => {
            let res = crate::service::uninstall::run(&["service".into(), "uninstall".into()]);
            match &res {
                Ok(()) => info_box(&i18n::launcher_uninstall_ok()),
                Err(e) => error_box(&i18n::launcher_uninstall_failed(&e.to_string())),
            }
            res
        }
        ResolvedAction::ElevateAndUninstall => elevate(elevated_uninstall_args(i18n::get()), true),
    }
}

fn install_opts() -> crate::service::install::Opts {
    crate::service::install::Opts {
        lang: i18n::get(),
        enable_overlap: false,
        quic: bosphorus_core::config::QuicPolicy::default(),
        profile_dir: None,
        install_dir: None,
        start_demand: false,
        force: false,
    }
}

/// MessageBox the outcome of an install. Also called by the elevated
/// `service install --from-launcher` re-spawn.
pub fn show_install_result(res: &anyhow::Result<()>) {
    match res {
        Ok(()) => info_box(&i18n::launcher_install_ok()),
        Err(e) => error_box(&i18n::launcher_install_failed(&e.to_string())),
    }
}

/// MessageBox the outcome of an uninstall. Called by the elevated
/// `service uninstall --from-launcher` re-spawn.
pub fn show_uninstall_result(res: &anyhow::Result<()>) {
    match res {
        Ok(()) => info_box(&i18n::launcher_uninstall_ok()),
        Err(e) => error_box(&i18n::launcher_uninstall_failed(&e.to_string())),
    }
}

/// `ShellExecuteW "runas"` self re-spawn. `hidden` = the re-spawn shows its own
/// MessageBox (service install/uninstall); otherwise it gets a visible window
/// (the engine's live log).
fn elevate(args: Vec<OsString>, hidden: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let params = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let exe_w = wide(&exe.to_string_lossy());
    let params_w = wide(&params);
    let show = if hidden { SW_HIDE } else { SW_SHOWNORMAL };
    // SAFETY: both wide strings are NUL-terminated and outlive the call; a null
    // owner HWND / working directory are documented as valid.
    let h = unsafe {
        ShellExecuteW(
            HWND::default(),
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(params_w.as_ptr()),
            PCWSTR::null(),
            show,
        )
    };
    // > 32 means it launched; a smaller value is an error, most often 1223
    // (ERROR_CANCELLED — the user declined the UAC prompt).
    if h.0 as isize > 32 {
        if !hidden {
            println!("{}", i18n::t(Msg::TuiElevatedStarted));
        }
        Ok(())
    } else if hidden {
        warn_box(&i18n::launcher_elevate_cancelled());
        Ok(())
    } else {
        println!("{}", i18n::launcher_elevate_cancelled());
        pause();
        Ok(())
    }
}

fn toggle_lang() {
    i18n::set(match i18n::get() {
        i18n::Lang::En => i18n::Lang::Tr,
        i18n::Lang::Tr => i18n::Lang::En,
    });
}

fn pause() {
    println!("\n{}", i18n::t(Msg::TuiPressKey));
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
}

// --------------------------------------------------------------------------- //
//  The TUI itself (not unit-tested — terminal I/O, like the MessageBox helpers)
// --------------------------------------------------------------------------- //

/// Runs the arrow-key menu and returns the user's choice (`Quit` on Esc/Q).
/// Inline rows (status, check-filters, profile, folder, about, language) run
/// without leaving the menu. Falls back to a plain numbered prompt when the
/// console has no virtual-terminal support.
fn tui_menu(installed: bool) -> LauncherChoice {
    let mut guard = match TermGuard::enter() {
        Ok(g) => g,
        Err(_) => return plain_menu(installed),
    };
    let mut model = MenuModel::new(installed);
    loop {
        guard.paint(&frame(&model, i18n::get(), installed));
        let item = match read_key() {
            Key::Up => {
                model.up();
                continue;
            }
            Key::Down => {
                model.down();
                continue;
            }
            Key::Char('l') | Key::Char('L') => MenuItem::ToggleLang,
            Key::Esc | Key::Char('q') | Key::Char('Q') => return LauncherChoice::Quit,
            Key::Enter => model.selected(),
            Key::Char(_) | Key::Other => continue,
        };

        if item == MenuItem::ToggleLang {
            toggle_lang();
            continue;
        }
        if item.is_inline() {
            guard.suspend();
            run_inline(item);
            guard.resume();
            continue;
        }
        return match item {
            MenuItem::RunOnce => LauncherChoice::RunOnce,
            MenuItem::SelfTest => LauncherChoice::SelfTest,
            MenuItem::InstallService => LauncherChoice::InstallService,
            MenuItem::UninstallService => LauncherChoice::UninstallService,
            MenuItem::Quit => LauncherChoice::Quit,
            // is_inline() covered the rest
            _ => LauncherChoice::Quit,
        };
    }
}

/// Runs an inline menu row (its output goes to the normal screen; the caller
/// has left raw mode). Every branch ends with a "press Enter" pause so the
/// user can read it before the menu repaints.
fn run_inline(item: MenuItem) {
    match item {
        MenuItem::ShowStatus => {
            let _ = crate::service::status::run();
            pause();
        }
        MenuItem::CheckFilters => {
            let _ = crate::engine_cmd::check_filters();
            pause();
        }
        MenuItem::ProfileInfo => profile_info(),
        MenuItem::OpenDataFolder => {
            let dir = current_data_dir();
            let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
            println!("\n  {}", dir.display());
            pause();
        }
        MenuItem::About => {
            print_about();
            pause();
        }
        _ => {}
    }
}

/// `%ProgramData%\Bosphorus` once the service is installed, else
/// `%LOCALAPPDATA%\Bosphorus` (the interactive data root).
fn current_data_dir() -> std::path::PathBuf {
    if crate::service::is_installed() {
        crate::service::data_dir()
    } else {
        std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("Bosphorus")
    }
}

fn profiles_dir() -> std::path::PathBuf {
    current_data_dir().join("profiles")
}

/// Newest `*.json` under `profiles/`, with a crude target / active count.
fn profile_info() {
    let dir = profiles_dir();
    let newest = std::fs::read_dir(&dir).ok().into_iter().flatten().flatten().filter(|e| {
        e.path().extension().and_then(|x| x.to_str()) == Some("json")
    });
    let newest = newest.max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    match newest {
        None => {
            println!("\n  {}", i18n::t(Msg::TuiProfileNone));
            pause();
        }
        Some(entry) => {
            let path = entry.path();
            println!("\n  {}", path.display());
            if let Ok(txt) = std::fs::read_to_string(&path) {
                let targets = txt.matches("\"key\"").count();
                let active = txt.matches("\"Active\"").count();
                println!("  targets: {targets}   active: {active}");
            }
            println!("\n  {}", i18n::t(Msg::TuiProfileDeletePrompt));
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
            if s.trim().eq_ignore_ascii_case("d") {
                match std::fs::remove_file(&path) {
                    Ok(()) => println!("\n  {}", i18n::t(Msg::TuiProfileDeleted)),
                    Err(e) => println!("\n  {e}"),
                }
                pause();
            }
        }
    }
}

fn print_about() {
    println!("\n  Bosphorus — self-learning DPI bypass");
    println!("  WinDivert 2.2   service name: {}", crate::service::SERVICE_NAME);
    println!("  data:     {}", current_data_dir().display());
    println!("  profiles: {}", profiles_dir().display());
    println!("  logs:     {}", crate::service::logs_dir().display());
}

fn item_label(item: MenuItem, lang: i18n::Lang) -> String {
    match item {
        MenuItem::RunOnce => i18n::t(Msg::MenuRunOnce).to_string(),
        MenuItem::SelfTest => i18n::t(Msg::MenuSelfTest).to_string(),
        MenuItem::InstallService => i18n::t(Msg::MenuInstall).to_string(),
        MenuItem::UninstallService => i18n::t(Msg::MenuUninstall).to_string(),
        MenuItem::ShowStatus => i18n::t(Msg::MenuStatus).to_string(),
        MenuItem::CheckFilters => i18n::t(Msg::MenuCheckFilters).to_string(),
        MenuItem::ProfileInfo => i18n::t(Msg::MenuProfile).to_string(),
        MenuItem::OpenDataFolder => i18n::t(Msg::MenuOpenFolder).to_string(),
        MenuItem::About => i18n::t(Msg::MenuAbout).to_string(),
        MenuItem::ToggleLang => format!(
            "{}: {}",
            i18n::t(Msg::MenuLanguage),
            lang_code(lang).to_uppercase()
        ),
        MenuItem::Quit => i18n::t(Msg::MenuQuit).to_string(),
    }
}

/// One full-screen frame. `i18n::t` is read fresh here, so a language toggle
/// shows on the very next paint with no extra plumbing.
fn frame(model: &MenuModel, lang: i18n::Lang, installed: bool) -> String {
    let mut s = String::from("\x1b[2J\x1b[H");
    s.push_str("\r\n  \x1b[1;36m+-----------------------------------+\x1b[0m\r\n");
    s.push_str("  \x1b[1;36m|\x1b[0m   \x1b[1mBOSPHORUS\x1b[0m  \x1b[2mDPI bypass\x1b[0m              \x1b[1;36m|\x1b[0m\r\n");
    s.push_str("  \x1b[1;36m+-----------------------------------+\x1b[0m\r\n\r\n");

    let svc = if installed {
        i18n::t(Msg::TuiSvcInstalled)
    } else {
        i18n::t(Msg::TuiSvcNotInstalled)
    };
    s.push_str(&format!("  \x1b[2m{svc}\x1b[0m\r\n\r\n"));

    for (i, item) in model.items.iter().enumerate() {
        let label = item_label(*item, lang);
        if i == model.cursor {
            s.push_str(&format!("  \x1b[7m  {label}  \x1b[0m\r\n"));
        } else {
            s.push_str(&format!("    {label}\r\n"));
        }
    }
    s.push_str(&format!("\r\n  \x1b[2m{}\x1b[0m\r\n", i18n::t(Msg::TuiHelp)));
    s
}

/// VT-unavailable fallback: a numbered prompt. Rarely reached (VT processing
/// has shipped in the Windows console since 2015).
fn plain_menu(installed: bool) -> LauncherChoice {
    let model = MenuModel::new(installed);
    println!("\nBosphorus\n");
    for (i, item) in model.items.iter().enumerate() {
        println!("  {}) {}", i + 1, item_label(*item, i18n::get()));
    }
    print!("\n> ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return LauncherChoice::Quit;
    }
    let idx = match line.trim().parse::<usize>() {
        Ok(n) if (1..=model.items.len()).contains(&n) => n - 1,
        _ => return LauncherChoice::Quit,
    };
    let item = model.items[idx];
    if item == MenuItem::ToggleLang {
        toggle_lang();
        return plain_menu(installed);
    }
    if item.is_inline() {
        run_inline(item);
        return plain_menu(installed);
    }
    match item {
        MenuItem::RunOnce => LauncherChoice::RunOnce,
        MenuItem::SelfTest => LauncherChoice::SelfTest,
        MenuItem::InstallService => LauncherChoice::InstallService,
        MenuItem::UninstallService => LauncherChoice::UninstallService,
        _ => LauncherChoice::Quit,
    }
}

// --- console raw-mode guard --------------------------------------------------

/// Owns the console-mode / output-code-page overrides for the duration of the
/// menu and restores them on `Drop` — including on an unwinding panic
/// (`panic = "unwind"` is load-bearing in the workspace release profile).
struct TermGuard {
    out: HANDLE,
    inp: HANDLE,
    out_mode: CONSOLE_MODE,
    in_mode: CONSOLE_MODE,
    out_cp: u32,
}

impl TermGuard {
    fn enter() -> anyhow::Result<Self> {
        // SAFETY: standard GetStdHandle / Get-Set-ConsoleMode calls; every
        // handle is a pseudo-handle we do not close, and the out-params are
        // correctly sized.
        unsafe {
            let out = GetStdHandle(STD_OUTPUT_HANDLE)?;
            let inp = GetStdHandle(STD_INPUT_HANDLE)?;
            let mut out_mode = CONSOLE_MODE::default();
            let mut in_mode = CONSOLE_MODE::default();
            if !GetConsoleMode(out, &mut out_mode).as_bool()
                || !GetConsoleMode(inp, &mut in_mode).as_bool()
            {
                anyhow::bail!("no console mode (not a real console?)");
            }
            let out_cp = GetConsoleOutputCP();

            let vt = CONSOLE_MODE(
                out_mode.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0 | ENABLE_PROCESSED_OUTPUT.0,
            );
            if !SetConsoleMode(out, vt).as_bool() {
                anyhow::bail!("virtual-terminal output unsupported");
            }
            let raw_in = CONSOLE_MODE(
                in_mode.0
                    & !(ENABLE_LINE_INPUT.0 | ENABLE_ECHO_INPUT.0 | ENABLE_PROCESSED_INPUT.0),
            );
            let _ = SetConsoleMode(inp, raw_in);
            let _ = SetConsoleOutputCP(65001); // UTF-8: arrows + Turkish glyphs

            print!("\x1b[?1049h\x1b[?25l"); // alt screen, hide cursor
            let _ = std::io::stdout().flush();
            Ok(Self { out, inp, out_mode, in_mode, out_cp })
        }
    }

    fn paint(&self, frame: &str) {
        print!("{frame}");
        let _ = std::io::stdout().flush();
    }

    /// Drop back to the normal screen with cooked input so an inline action's
    /// output scrolls and `read_line` works.
    fn suspend(&mut self) {
        print!("\x1b[?25h\x1b[?1049l");
        let _ = std::io::stdout().flush();
        // SAFETY: restoring the modes captured in `enter`.
        unsafe {
            let _ = SetConsoleMode(self.out, self.out_mode);
            let _ = SetConsoleMode(self.inp, self.in_mode);
        }
    }

    /// Re-enter the alt screen / raw input after `suspend`.
    fn resume(&mut self) {
        // SAFETY: same VT/raw modes as `enter`.
        unsafe {
            let vt = CONSOLE_MODE(
                self.out_mode.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0 | ENABLE_PROCESSED_OUTPUT.0,
            );
            let _ = SetConsoleMode(self.out, vt);
            let raw_in = CONSOLE_MODE(
                self.in_mode.0
                    & !(ENABLE_LINE_INPUT.0 | ENABLE_ECHO_INPUT.0 | ENABLE_PROCESSED_INPUT.0),
            );
            let _ = SetConsoleMode(self.inp, raw_in);
        }
        print!("\x1b[?1049h\x1b[?25l");
        let _ = std::io::stdout().flush();
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        print!("\x1b[?25h\x1b[?1049l"); // show cursor, leave alt screen
        let _ = std::io::stdout().flush();
        // SAFETY: restoring the exact modes/CP we captured in `enter`.
        unsafe {
            let _ = SetConsoleMode(self.out, self.out_mode);
            let _ = SetConsoleMode(self.inp, self.in_mode);
            let _ = SetConsoleOutputCP(self.out_cp);
        }
    }
}

// --- key input ------------------------------------------------------------

enum Key {
    Up,
    Down,
    Enter,
    Esc,
    Char(char),
    Other,
}

fn read_key() -> Key {
    let mut buf = [INPUT_RECORD::default(); 1];
    loop {
        // SAFETY: `buf` is a valid 1-element slice; `n` is a valid out-param.
        let inp = match unsafe { GetStdHandle(STD_INPUT_HANDLE) } {
            Ok(h) => h,
            Err(_) => return Key::Esc,
        };
        let mut n = 0u32;
        if !unsafe { ReadConsoleInputW(inp, &mut buf, &mut n) }.as_bool() || n == 0 {
            return Key::Esc; // read failure — treat as quit
        }
        let rec = buf[0];
        if u32::from(rec.EventType) != KEY_EVENT {
            continue;
        }
        // SAFETY: EventType == KEY_EVENT, so the KeyEvent arm of the union is live.
        let ke = unsafe { rec.Event.KeyEvent };
        if !ke.bKeyDown.as_bool() {
            continue;
        }
        return match ke.wVirtualKeyCode {
            0x26 => Key::Up,
            0x28 => Key::Down,
            0x0D => Key::Enter,
            0x1B => Key::Esc,
            _ => {
                // SAFETY: UnicodeChar arm of the uChar union.
                let ch = unsafe { ke.uChar.UnicodeChar };
                match char::from_u32(u32::from(ch)) {
                    Some(c) if !c.is_control() => Key::Char(c),
                    _ => Key::Other,
                }
            }
        };
    }
}

// --------------------------------------------------------------------------- //
//  Win32 probes (thin wrappers; the routing they feed is what's tested)
// --------------------------------------------------------------------------- //

/// True when this process is the only one attached to its console — i.e. the
/// console was created because Explorer launched the exe, or (same shape)
/// because `elevate()`'s `ShellExecuteW "runas"` spawned a fresh elevated
/// process with its own new console. `> 1` means we share a console with a
/// shell that was already there (typed at a prompt) — used by `main`'s
/// `finish()` to decide whether a window would otherwise vanish with no
/// prompt to return to.
pub(crate) fn is_double_click() -> bool {
    let mut list = [0u32; 4];
    // SAFETY: `list` is a valid, writable buffer of `list.len()` u32s.
    let n = unsafe { GetConsoleProcessList(&mut list) };
    n <= 1
}

fn is_elevated() -> bool {
    // SAFETY: standard OpenProcessToken / GetTokenInformation dance; `token` is
    // closed on every path, the out-params are correctly sized.
    unsafe {
        let mut token = HANDLE::default();
        if !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).as_bool() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .as_bool();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

// --- MessageBox helpers ---------------------------------------------------

fn message_box(body: &str, style: MESSAGEBOX_STYLE) {
    let body_w = wide(body);
    // SAFETY: null owner HWND is allowed; both wide strings are NUL-terminated.
    unsafe {
        MessageBoxW(HWND::default(), PCWSTR(body_w.as_ptr()), w!("Bosphorus"), MB_OK | style);
    }
}
fn info_box(body: &str) {
    message_box(body, MB_ICONINFORMATION);
}
fn warn_box(body: &str) {
    message_box(body, MB_ICONWARNING);
}
fn error_box(body: &str) {
    message_box(body, MB_ICONERROR);
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    fn as_strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|o| o.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn from_a_shell_no_args_always_shows_usage() {
        assert_eq!(decide(false), Screen::Usage);
        assert_eq!(decide(true), Screen::Tui);
    }

    #[test]
    fn menu_items_depend_on_installed_state() {
        let not_installed = MenuModel::items_for(false);
        let installed = MenuModel::items_for(true);
        // the install-vs-status/uninstall swap is the whole "already installed" branch
        assert!(not_installed.contains(&MenuItem::InstallService));
        assert!(!not_installed.contains(&MenuItem::ShowStatus));
        assert!(!not_installed.contains(&MenuItem::UninstallService));
        assert!(!installed.contains(&MenuItem::InstallService));
        assert!(installed.contains(&MenuItem::ShowStatus));
        assert!(installed.contains(&MenuItem::UninstallService));
        // rows present in both, order stable at the ends
        for m in [&not_installed, &installed] {
            assert_eq!(m.first(), Some(&MenuItem::RunOnce));
            assert_eq!(m.last(), Some(&MenuItem::Quit));
            assert!(m.contains(&MenuItem::CheckFilters));
            assert!(m.contains(&MenuItem::SelfTest));
            assert!(m.contains(&MenuItem::ProfileInfo));
            assert!(m.contains(&MenuItem::About));
            assert!(m.contains(&MenuItem::ToggleLang));
        }
    }

    #[test]
    fn menu_cursor_wraps_both_ways() {
        let mut m = MenuModel::new(false);
        let n = m.items.len();
        assert_eq!(m.cursor, 0);
        m.up();
        assert_eq!(m.cursor, n - 1);
        assert_eq!(m.selected(), MenuItem::Quit);
        m.down();
        assert_eq!(m.cursor, 0);
        assert_eq!(m.selected(), MenuItem::RunOnce);
    }

    #[test]
    fn inline_vs_exit_rows_are_classified() {
        for i in [
            MenuItem::ShowStatus,
            MenuItem::CheckFilters,
            MenuItem::ProfileInfo,
            MenuItem::OpenDataFolder,
            MenuItem::About,
            MenuItem::ToggleLang,
        ] {
            assert!(i.is_inline(), "{i:?}");
        }
        for i in [
            MenuItem::RunOnce,
            MenuItem::SelfTest,
            MenuItem::InstallService,
            MenuItem::UninstallService,
            MenuItem::Quit,
        ] {
            assert!(!i.is_inline(), "{i:?}");
        }
    }

    #[test]
    fn dispatch_choice_matrix_covers_the_4b_routing_plus_two_way_elevation() {
        use LauncherChoice as C;
        use ResolvedAction as R;
        // 4b: install decision, now at the (choice, elevated) seam
        assert_eq!(dispatch_choice(C::InstallService, false), R::ElevateAndInstall);
        assert_eq!(dispatch_choice(C::InstallService, true), R::InstallHere);
        // new two-way elevation: run once + self-test behave like install
        assert_eq!(dispatch_choice(C::RunOnce, false), R::ElevateAndRun);
        assert_eq!(dispatch_choice(C::RunOnce, true), R::RunEngineHere);
        assert_eq!(dispatch_choice(C::SelfTest, false), R::ElevateAndSelfTest);
        assert_eq!(dispatch_choice(C::SelfTest, true), R::RunSelfTestHere);
        // uninstall
        assert_eq!(dispatch_choice(C::UninstallService, false), R::ElevateAndUninstall);
        assert_eq!(dispatch_choice(C::UninstallService, true), R::UninstallHere);
        // quit is quit (status / check-filters / profile / about run inline, never here)
        assert_eq!(dispatch_choice(C::Quit, false), R::Exit);
        assert_eq!(dispatch_choice(C::Quit, true), R::Exit);
    }

    #[test]
    fn elevated_reinvoke_argv_per_action() {
        assert_eq!(
            as_strs(&elevated_install_args(Lang::En)),
            ["service", "install", "--lang", "en", "--from-launcher"]
        );
        assert_eq!(
            as_strs(&elevated_uninstall_args(Lang::Tr)),
            ["service", "uninstall", "--lang", "tr", "--from-launcher"]
        );
        assert_eq!(as_strs(&elevated_run_args(Lang::En)), ["--engine", "--lang", "en"]);
        assert_eq!(as_strs(&elevated_selftest_args(Lang::En)), ["--selftest", "--lang", "en"]);
        assert_eq!(elevated_run_args(Lang::Tr)[2], "tr");
    }
}
