//! Double-click entry point (4b).
//!
//! When `bosphorus.exe` is launched from Explorer — no arguments, and this
//! process owns its console — there is no terminal to print to. Instead, guide
//! the user through installing the Windows service: elevate through UAC if
//! needed, run `service install`, and report the outcome in a MessageBox.
//!
//! Running `bosphorus` with no arguments *from a shell* is unchanged: print the
//! CLI usage and exit 2.

use std::ffi::{c_void, OsString};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MESSAGEBOX_STYLE, SW_HIDE,
};

use crate::i18n;

/// Internal marker appended to the elevated re-spawn's argv so that
/// `service install` pops a MessageBox with its result (the re-spawn's console
/// is hidden — nobody would see the printed lines).
pub const FROM_LAUNCHER_FLAG: &str = "--from-launcher";

/// What the no-arguments entry point should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Not a double-click (started from a shell): print CLI usage, exit 2.
    ShowUsage,
    /// Double-clicked, the service already exists: informational box, no change.
    AlreadyInstalled,
    /// Double-clicked, not elevated: re-spawn self elevated to install.
    ElevateAndInstall,
    /// Double-clicked and already elevated: install here, box the result.
    InstallHere,
}

/// Pure routing decision. The three inputs are the only Win32 probes the
/// launcher makes; keeping the branching here makes it unit-testable.
pub fn decide(double_click: bool, elevated: bool, installed: bool) -> Action {
    if !double_click {
        return Action::ShowUsage;
    }
    if installed {
        return Action::AlreadyInstalled;
    }
    if elevated {
        Action::InstallHere
    } else {
        Action::ElevateAndInstall
    }
}

/// The argv the elevated re-spawn is invoked with.
pub fn elevated_install_args(lang: i18n::Lang) -> Vec<OsString> {
    let code = match lang {
        i18n::Lang::En => "en",
        i18n::Lang::Tr => "tr",
    };
    vec![
        "service".into(),
        "install".into(),
        "--lang".into(),
        code.into(),
        FROM_LAUNCHER_FLAG.into(),
    ]
}

pub fn run() -> anyhow::Result<()> {
    let action = decide(is_double_click(), is_elevated(), crate::service::is_installed());
    if action != Action::ShowUsage {
        // Explorer gave us a console window that flashed on screen; the UI from
        // here on is MessageBox only. Drop it.
        // SAFETY: no arguments; failure (no console attached) is fine to ignore.
        unsafe {
            let _ = FreeConsole();
        }
    }
    match action {
        Action::ShowUsage => {
            crate::usage();
            std::process::exit(2);
        }
        Action::AlreadyInstalled => {
            info_box(&i18n::launcher_already_installed());
            Ok(())
        }
        Action::InstallHere => {
            let opts = crate::service::install::Opts {
                lang: i18n::get(),
                enable_overlap: false,
                profile_dir: None,
                install_dir: None,
                start_demand: false,
                force: false,
            };
            let res = crate::service::install::install(&opts);
            show_install_result(&res);
            res
        }
        Action::ElevateAndInstall => elevate_and_reinvoke(i18n::get()),
    }
}

/// MessageBox the outcome of an install. Called here (already-elevated path)
/// and by the elevated `service install --from-launcher` re-spawn.
pub fn show_install_result(res: &anyhow::Result<()>) {
    match res {
        Ok(()) => info_box(&i18n::launcher_install_ok()),
        Err(e) => error_box(&i18n::launcher_install_failed(&e.to_string())),
    }
}

fn elevate_and_reinvoke(lang: i18n::Lang) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let params = elevated_install_args(lang)
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let exe_w = wide(&exe.to_string_lossy());
    let params_w = wide(&params);
    // SAFETY: both strings are NUL-terminated and outlive the call; a null
    // owner HWND and null working directory are documented as valid.
    let h = unsafe {
        ShellExecuteW(
            HWND::default(),
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(params_w.as_ptr()),
            PCWSTR::null(),
            SW_HIDE,
        )
    };
    // ShellExecuteW returns a fake HINSTANCE; > 32 means it launched. A smaller
    // value is an error — most often 1223 (ERROR_CANCELLED: user declined UAC).
    if h.0 as isize > 32 {
        Ok(()) // the elevated instance now owns the flow and shows its own box
    } else {
        warn_box(&i18n::launcher_elevate_cancelled());
        Ok(())
    }
}

// --- Win32 probes (thin wrappers; the routing they feed is what's tested) ---

/// True when this process is the only one attached to its console — i.e. the
/// console was created because Explorer launched the exe. A count `> 1` means
/// we were started from an existing shell (leave stdout/usage behaviour alone).
fn is_double_click() -> bool {
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

    #[test]
    fn from_a_shell_no_args_always_shows_usage() {
        assert_eq!(decide(false, false, false), Action::ShowUsage);
        assert_eq!(decide(false, true, true), Action::ShowUsage);
    }

    #[test]
    fn double_click_routing_matrix() {
        // not installed
        assert_eq!(decide(true, false, false), Action::ElevateAndInstall);
        assert_eq!(decide(true, true, false), Action::InstallHere);
        // already installed -> informational only, regardless of elevation
        assert_eq!(decide(true, false, true), Action::AlreadyInstalled);
        assert_eq!(decide(true, true, true), Action::AlreadyInstalled);
    }

    #[test]
    fn elevated_reinvoke_argv_is_service_install_from_launcher() {
        let en: Vec<String> = elevated_install_args(Lang::En)
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();
        assert_eq!(en, ["service", "install", "--lang", "en", "--from-launcher"]);
        assert_eq!(elevated_install_args(Lang::Tr)[3], "tr");
    }
}
