//! Minimal hand-rolled message catalog. English + Turkish, default English.
//!
//! Deliberately not an i18n crate: ~2 languages, a small fixed set of strings,
//! and a `match` that the compiler forces to be exhaustive — a missing
//! translation is a build error, not a silent runtime fallback. Zero new
//! dependencies.
//!
//! Scope: user-facing CLI text on the `--engine` path (startup lines, the
//! discovery-summary table, its error messages, and the auto-discovery
//! warning). Developer `tracing` output and the diagnostic sub-commands
//! (`--selftest`, `--passthru`, `--observe`, `--discovery-demo`, `--mem-bench`)
//! stay English.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Tr,
}

static CURRENT: AtomicU8 = AtomicU8::new(Lang::En as u8);

pub fn set(l: Lang) {
    CURRENT.store(l as u8, Ordering::Relaxed);
}

pub fn get() -> Lang {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Lang::Tr,
        _ => Lang::En,
    }
}

/// Parse a `--lang` / `BOSPHORUS_LANG` value. `None` for anything unrecognised.
pub fn parse(s: &str) -> Option<Lang> {
    match s.trim().to_ascii_lowercase().as_str() {
        "en" | "en-us" | "english" => Some(Lang::En),
        "tr" | "tr-tr" | "turkish" | "turkce" | "türkçe" => Some(Lang::Tr),
        _ => None,
    }
}

/// Static, parameter-free user-facing strings.
#[derive(Clone, Copy)]
pub enum Msg {
    /// The auto-discovery warning (shown on `service install` and at the start
    /// of a one-shot discovery run).
    DiscoveryWarning,
    FilterCompiledOk,
    EngineModeForced,
    RunStopCtrlC,
    OverlapEnabledWarning,
    NoSuccessYet,
    NotBlockedPassthrough,
    NoneExhausted,
    /// `[disk]` / `[new ]` origin tags — kept identical in both languages.
    OriginDisk,
    OriginNew,
    HintElevated,
    HintDriverColocated,

    // --- QUIC policy (M9) ---
    /// `--quic all`: every HTTP/3 attempt on the machine is refused.
    QuicBlockAll,
    /// `--quic blocked` (the default): only censored destinations lose HTTP/3.
    QuicBlockSelective,
    /// `--quic off`: HTTP/3 is left alone entirely.
    QuicOff,

    // --- service (4a) ---
    NeedAdmin,
    SvcRunNotFromConsole,
    SvcNotInstalled,
    SvcUsage,
    PreflightHvci,

    // --- interactive launcher TUI (4c) ---
    MenuRunOnce,
    MenuSelfTest,
    MenuInstall,
    MenuStatus,
    MenuUninstall,
    MenuCheckFilters,
    MenuProfile,
    MenuOpenFolder,
    MenuAbout,
    MenuLanguage,
    MenuQuit,
    TuiHelp,
    TuiSvcInstalled,
    TuiSvcNotInstalled,
    TuiElevatedStarted,
    TuiPressKey,
    TuiProfileNone,
    TuiProfileDeletePrompt,
    TuiProfileDeleted,
}

pub fn t(m: Msg) -> &'static str {
    use Lang::{En, Tr};
    use Msg::*;
    match (get(), m) {
        (En, DiscoveryWarning) => "Bosphorus runs fully automatically. You may see connection problems on some sites for a while — this is normal: it is searching for the best method for your network. Please give it some time.",
        (Tr, DiscoveryWarning) => "Bosphorus tamamen otomatiktir. Bazı sitelerde erişim problemi yaşayabilirsiniz — bu tamamen normal, sizin için en iyi yöntemi aramaktadır, biraz zaman verin.",

        (En, FilterCompiledOk) => "filter compiled OK",
        (Tr, FilterCompiledOk) => "filtre derlendi: OK",

        (En, EngineModeForced) => "engine mode = forced strategy",
        (Tr, EngineModeForced) => "motor modu = sabit strateji",

        (En, RunStopCtrlC) => "run: stop with Ctrl+C",
        (Tr, RunStopCtrlC) => "çalışma: durdurmak için Ctrl+C",

        (En, OverlapEnabledWarning) => "  ! --enable-overlap: OverlapDisorder candidates are in the sweep; they can break a handshake on a first-received-wins server",
        (Tr, OverlapEnabledWarning) => "  ! --enable-overlap: OverlapDisorder adayları taramada; ilk-geleni-kabul eden bir sunucuda el sıkışmayı bozabilirler",

        (En, NoSuccessYet) => "no success yet",
        (Tr, NoSuccessYet) => "henüz başarı yok",

        (En, NotBlockedPassthrough) => "not blocked (passthrough)",
        (Tr, NotBlockedPassthrough) => "engelli değil (passthrough)",

        (En, NoneExhausted) => "NONE succeeded",
        (Tr, NoneExhausted) => "HİÇBİRİ başarılı olmadı",

        (_, OriginDisk) => "disk",
        (_, OriginNew) => "new ",

        (En, HintElevated) => " — run from an elevated (Administrator) PowerShell",
        (Tr, HintElevated) => " — yönetici (Administrator) PowerShell'den çalıştırın",

        (En, HintDriverColocated) => " — WinDivert64.sys is not in the same folder as WinDivert.dll",
        (Tr, HintDriverColocated) => " — WinDivert64.sys, WinDivert.dll ile aynı klasörde değil",

        (En, QuicBlockAll) => "QUIC: every HTTP/3 connection is refused, so everything falls back to TCP",
        (Tr, QuicBlockAll) => "QUIC: tüm HTTP/3 bağlantıları reddediliyor, her şey TCP'ye düşecek",

        (En, QuicBlockSelective) => "QUIC: HTTP/3 is refused only for sites a censor was caught interfering with",
        (Tr, QuicBlockSelective) => "QUIC: HTTP/3 yalnızca sansürlendiği tespit edilen siteler için reddediliyor",

        (En, QuicOff) => "QUIC: left untouched (a blocked site may keep failing over HTTP/3)",
        (Tr, QuicOff) => "QUIC: hiç dokunulmuyor (engelli bir site HTTP/3 üzerinden açılmamaya devam edebilir)",

        (En, NeedAdmin) => "This command needs an elevated (Administrator) console.",
        (Tr, NeedAdmin) => "Bu komut yönetici (Administrator) konsol gerektirir.",

        (En, SvcRunNotFromConsole) => "`service run` is the SCM entry point. For an interactive run use `bosphorus --engine`.",
        (Tr, SvcRunNotFromConsole) => "`service run` SCM giriş noktasıdır. Etkileşimli çalışma için `bosphorus --engine` kullanın.",

        (En, SvcNotInstalled) => "Bosphorus service: not installed.",
        (Tr, SvcNotInstalled) => "Bosphorus hizmeti: kurulu değil.",

        (En, SvcUsage) => "usage: bosphorus service <install|uninstall|run|status>",
        (Tr, SvcUsage) => "kullanım: bosphorus service <install|uninstall|run|status>",

        (En, PreflightHvci) => "The WinDivert driver would not load. Likely HVCI / Memory Integrity, Smart App Control, or a WDAC policy is blocking it — the service would not start either.",
        (Tr, PreflightHvci) => "WinDivert sürücüsü yüklenemedi. Muhtemelen HVCI / Bellek Bütünlüğü, Smart App Control veya bir WDAC politikası engelliyor — servis de başlamaz.",

        (En, MenuRunOnce) => "Run once (this session only)",
        (Tr, MenuRunOnce) => "Bir kez çalıştır (yalnızca bu oturum)",

        (En, MenuSelfTest) => "Test WinDivert on this PC",
        (Tr, MenuSelfTest) => "Bu bilgisayarda WinDivert'i test et",

        (En, MenuInstall) => "Install as a service (starts with Windows)",
        (Tr, MenuInstall) => "Hizmet olarak kur (Windows ile başlar)",

        (En, MenuStatus) => "Show service status",
        (Tr, MenuStatus) => "Hizmet durumunu göster",

        (En, MenuUninstall) => "Uninstall the service",
        (Tr, MenuUninstall) => "Hizmeti kaldır",

        (En, MenuCheckFilters) => "Check filter syntax (no Administrator needed)",
        (Tr, MenuCheckFilters) => "Filtre sözdizimini kontrol et (Yönetici gerekmez)",

        (En, MenuProfile) => "Discovery profile (view / reset)",
        (Tr, MenuProfile) => "Keşif profili (görüntüle / sıfırla)",

        (En, MenuOpenFolder) => "Open data folder",
        (Tr, MenuOpenFolder) => "Veri klasörünü aç",

        (En, MenuAbout) => "About",
        (Tr, MenuAbout) => "Hakkında",

        (En, MenuLanguage) => "Language",
        (Tr, MenuLanguage) => "Dil",

        (En, MenuQuit) => "Quit",
        (Tr, MenuQuit) => "Çık",

        (En, TuiHelp) => "\u{2191}\u{2193} move   Enter select   L language   Q quit",
        (Tr, TuiHelp) => "\u{2191}\u{2193} gez   Enter seç   L dil   Q çık",

        (En, TuiSvcInstalled) => "Service: installed",
        (Tr, TuiSvcInstalled) => "Hizmet: kurulu",

        (En, TuiSvcNotInstalled) => "Service: not installed",
        (Tr, TuiSvcNotInstalled) => "Hizmet: kurulu değil",

        (En, TuiElevatedStarted) => "Bosphorus started in a new window. You can close this one.",
        (Tr, TuiElevatedStarted) => "Bosphorus yeni bir pencerede başladı. Bu pencereyi kapatabilirsiniz.",

        (En, TuiPressKey) => "Press Enter to close this window.",
        (Tr, TuiPressKey) => "Bu pencereyi kapatmak için Enter'a basın.",

        (En, TuiProfileNone) => "No discovery profile yet — nothing has been learned.",
        (Tr, TuiProfileNone) => "Henüz keşif profili yok — hiçbir şey öğrenilmedi.",

        (En, TuiProfileDeletePrompt) => "Type d + Enter to delete this profile and relearn, or just Enter to go back:",
        (Tr, TuiProfileDeletePrompt) => "Bu profili silip yeniden öğrenmek için d + Enter, geri dönmek için sadece Enter:",

        (En, TuiProfileDeleted) => "Profile deleted. Bosphorus will relearn from scratch.",
        (Tr, TuiProfileDeleted) => "Profil silindi. Bosphorus sıfırdan öğrenecek.",
    }
}

// --- parameterised lines --------------------------------------------------

pub fn engine_mode_auto(grid: usize) -> String {
    match get() {
        Lang::En => format!("engine mode = auto-discovery (grid: {grid} strategies)"),
        Lang::Tr => format!("motor modu = otomatik keşif ({grid} stratejilik grid)"),
    }
}

pub fn profile_line(path: &str) -> String {
    match get() {
        Lang::En => format!("profile: {path}"),
        Lang::Tr => format!("profil: {path}"),
    }
}

pub fn net_line(human: &str, restored: usize) -> String {
    match get() {
        Lang::En => format!("         net: {human}   ({restored} target(s) restored)"),
        Lang::Tr => format!("         ağ: {human}   ({restored} hedef geri yüklendi)"),
    }
}

pub fn run_timed(secs: u64) -> String {
    match get() {
        Lang::En => format!("run: {secs}s, then stops automatically"),
        Lang::Tr => format!("çalışma: {secs}s, sonra otomatik durur"),
    }
}

pub fn err_filter_build(e: &str) -> String {
    match get() {
        Lang::En => format!("filter build: {e}"),
        Lang::Tr => format!("filtre oluşturma: {e}"),
    }
}

pub fn err_filter_rejected(pos: u32, msg: &str) -> String {
    match get() {
        Lang::En => format!("main filter rejected at pos {pos}: {msg}"),
        Lang::Tr => format!("ana filtre {pos}. konumda reddedildi: {msg}"),
    }
}

pub fn err_windivert_open(e: &str, hint: &str) -> String {
    match get() {
        Lang::En => format!("WinDivertOpen failed: {e}{hint}"),
        Lang::Tr => format!("WinDivertOpen başarısız: {e}{hint}"),
    }
}

pub fn err_quic_block_open(e: &str) -> String {
    match get() {
        Lang::En => format!("could not open the QUIC-block handle: {e}"),
        Lang::Tr => format!("QUIC engelleme tutacağı açılamadı: {e}"),
    }
}

pub fn engine_finished(packets: u64, kb: u64, dropped: u64, batches: u64) -> String {
    match get() {
        Lang::En => {
            format!("engine finished: {packets} packets, {kb} KB, {dropped} dropped, {batches} batched")
        }
        Lang::Tr => {
            format!("motor bitti: {packets} paket, {kb} KB, {dropped} düşürüldü, {batches} yığın")
        }
    }
}

pub fn summary_title(grid: usize) -> String {
    match get() {
        Lang::En => format!("--- discovery summary ({grid}-strategy grid) ---"),
        Lang::Tr => format!("--- keşif özeti ({grid} stratejilik grid) ---"),
    }
}

/// `Exhausted` row body: "{tried}/{total} strategies tried, NONE succeeded".
pub fn summary_exhausted(tried: usize, total: usize) -> String {
    match get() {
        Lang::En => format!("{tried}/{total} strategies tried, {}", t(Msg::NoneExhausted)),
        Lang::Tr => format!("{tried}/{total} strateji denendi, {}", t(Msg::NoneExhausted)),
    }
}

/// `Active` (promoted strategy) row body: "active: {strategy}".
pub fn summary_active(strategy: &str) -> String {
    match get() {
        Lang::En => format!("active: {strategy}"),
        Lang::Tr => format!("aktif: {strategy}"),
    }
}

/// In-progress row body.
pub fn summary_progress(
    tried: usize,
    total: usize,
    in_flight: usize,
    age: &str,
    best: &str,
) -> String {
    match get() {
        Lang::En => {
            format!("{tried}/{total} tried (in_flight={in_flight}, last try {age}), {best}")
        }
        Lang::Tr => {
            format!("{tried}/{total} denendi (in_flight={in_flight}, son deneme {age}), {best}")
        }
    }
}

pub fn best_so_far(desc: &str, successes: u32, trials: u32) -> String {
    match get() {
        Lang::En => format!("best: {desc} ({successes}/{trials})"),
        Lang::Tr => format!("en iyi: {desc} ({successes}/{trials})"),
    }
}

pub fn secs_ago(secs: u64) -> String {
    match get() {
        Lang::En => format!("{secs}s ago"),
        Lang::Tr => format!("{secs}s önce"),
    }
}

// --- service (4a) -------------------------------------------------------------

pub fn svc_state_line(state: &str) -> String {
    match get() {
        Lang::En => format!("Bosphorus service: {state}"),
        Lang::Tr => format!("Bosphorus hizmeti: {state}"),
    }
}

pub fn svc_last_write(name: &str, secs: u64) -> String {
    match get() {
        Lang::En => format!("last learning write: {name} ({secs}s ago)"),
        Lang::Tr => format!("son öğrenme yazımı: {name} ({secs}s önce)"),
    }
}

pub fn preflight_fail(err: &str) -> String {
    match get() {
        Lang::En => format!("pre-flight WinDivertOpen failed: {err}\n{}", t(Msg::PreflightHvci)),
        Lang::Tr => format!("ön-kontrol WinDivertOpen başarısız: {err}\n{}", t(Msg::PreflightHvci)),
    }
}

pub fn preflight_warn_forced(err: &str) -> String {
    match get() {
        Lang::En => format!("pre-flight WinDivertOpen failed: {err} — continuing anyway (--force)"),
        Lang::Tr => format!("ön-kontrol WinDivertOpen başarısız: {err} — yine de devam ediliyor (--force)"),
    }
}

pub fn svc_created(name: &str) -> String {
    match get() {
        Lang::En => format!("service '{name}' created (LocalSystem, auto-start) and started."),
        Lang::Tr => format!("'{name}' hizmeti oluşturuldu (LocalSystem, otomatik-başlangıç) ve başlatıldı."),
    }
}

pub fn svc_deleted(name: &str) -> String {
    match get() {
        Lang::En => format!("service '{name}' stopped and deleted."),
        Lang::Tr => format!("'{name}' hizmeti durduruldu ve silindi."),
    }
}

/// The post-install "verify it actually came up" block. The intro is
/// translated; the PowerShell commands are the same in both languages.
pub fn install_verification() -> String {
    let intro = match get() {
        Lang::En => "\nIMPORTANT — the driver can be blocked at boot with no visible error.\nRun these now to confirm the service actually started:",
        Lang::Tr => "\nÖNEMLİ — sürücü boot'ta görünür hata vermeden engellenebilir.\nGerçekten başladığını doğrulamak için şimdi şunları çalıştırın:",
    };
    format!(
        "{intro}\n\
         \n\
         Get-Service Bosphorus                     # Status = Running olmalı\n\
         Get-Service WinDivert ; sc.exe query WinDivert\n\
         Get-WinEvent -LogName Application -MaxEvents 30 |\n\
         \x20\x20Where-Object ProviderName -eq 'Bosphorus' | Format-List TimeCreated,LevelDisplayName,Message\n\
         Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 20 |\n\
         \x20\x20Where-Object Message -match 'WinDivert'\n\
         Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard |\n\
         \x20\x20Select-Object -ExpandProperty SecurityServicesRunning       # '2' -> HVCI aktif\n\
         Get-ChildItem \"$env:ProgramData\\Bosphorus\\profiles\\*.json\" | Select-Object Name,LastWriteTime\n"
    )
}

// --- interactive launcher (4b) ---------------------------------------------

/// User declined the UAC prompt.
pub fn launcher_elevate_cancelled() -> String {
    match get() {
        Lang::En => {
            "Administrator permission was not granted.\nBosphorus was not installed.".into()
        }
        Lang::Tr => "Yönetici izni verilmedi.\nBosphorus kurulmadı.".into(),
    }
}

/// Install succeeded (shown by the launcher / its elevated re-spawn).
pub fn launcher_install_ok() -> String {
    match get() {
        Lang::En => "Bosphorus is installed and running.\n\n\
                     It now works fully automatically in the background and starts with Windows.\n\n\
                     Re-open this launcher any time and choose \"Show service status\" to check on it."
            .into(),
        Lang::Tr => "Bosphorus kuruldu ve çalışıyor.\n\n\
                     Artık arka planda tamamen otomatik çalışır ve Windows ile birlikte başlar.\n\n\
                     Kontrol etmek için bu başlatıcıyı tekrar açıp \"Hizmet durumunu göster\"i seçin."
            .into(),
    }
}

/// Uninstall succeeded.
pub fn launcher_uninstall_ok() -> String {
    match get() {
        Lang::En => "The Bosphorus service was removed.".into(),
        Lang::Tr => "Bosphorus hizmeti kaldırıldı.".into(),
    }
}

/// Uninstall failed.
pub fn launcher_uninstall_failed(err: &str) -> String {
    match get() {
        Lang::En => format!("The Bosphorus service could not be removed.\n\n{err}"),
        Lang::Tr => format!("Bosphorus hizmeti kaldırılamadı.\n\n{err}"),
    }
}

/// Install failed (shown by the launcher / its elevated re-spawn).
pub fn launcher_install_failed(err: &str) -> String {
    match get() {
        Lang::En => format!(
            "Bosphorus could not be installed.\n\n{err}\n\n\
             If HVCI / Memory Integrity, Smart App Control, or a WDAC policy is active, the \
             WinDivert driver cannot load. Check the Event Log:\n\
             \x20\x20\x20\x20Get-WinEvent -LogName Application -MaxEvents 20 |\n\
             \x20\x20\x20\x20\x20\x20Where-Object ProviderName -eq 'Bosphorus'"
        ),
        Lang::Tr => format!(
            "Bosphorus kurulamadı.\n\n{err}\n\n\
             HVCI / Bellek Bütünlüğü, Smart App Control veya bir WDAC politikası etkinse \
             WinDivert sürücüsü yüklenemez. Olay Günlüğünü kontrol edin:\n\
             \x20\x20\x20\x20Get-WinEvent -LogName Application -MaxEvents 20 |\n\
             \x20\x20\x20\x20\x20\x20Where-Object ProviderName -eq 'Bosphorus'"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `CURRENT` is one process-global atomic. cargo test runs tests on
    // multiple threads by default, so any two tests that both `set()` it and
    // then assert on `t()`/`get()` race — one thread's `set(Tr)` can land
    // between another thread's `set(En)` and its assertion, failing a test
    // whose own code never changed. Every test below that touches `CURRENT`
    // takes this lock first so they run one at a time; a poisoned lock (an
    // earlier such test panicked mid-switch) still yields the guard, since
    // the only shared state at risk is `CURRENT` itself, always reset before
    // the guard drops.
    static LANG_TEST_LOCK: Mutex<()> = Mutex::new(());
    fn lock_lang() -> std::sync::MutexGuard<'static, ()> {
        LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn parse_accepts_both_and_rejects_junk() {
        assert_eq!(parse("en"), Some(Lang::En));
        assert_eq!(parse("TR"), Some(Lang::Tr));
        assert_eq!(parse(" tr-TR "), Some(Lang::Tr));
        assert_eq!(parse("de"), None);
    }

    #[test]
    fn catalogue_switches_with_the_global_lang() {
        let _guard = lock_lang();
        set(Lang::En);
        assert!(t(Msg::DiscoveryWarning).starts_with("Bosphorus runs fully automatically"));
        assert_eq!(engine_finished(1, 2, 3, 4), "engine finished: 1 packets, 2 KB, 3 dropped, 4 batched");

        set(Lang::Tr);
        assert!(t(Msg::DiscoveryWarning).starts_with("Bosphorus tamamen otomatiktir"));
        assert_eq!(engine_finished(1, 2, 3, 4), "motor bitti: 1 paket, 2 KB, 3 düşürüldü, 4 yığın");

        set(Lang::En); // don't leak state to other tests
    }

    #[test]
    fn origin_tags_are_language_independent() {
        let _guard = lock_lang();
        set(Lang::En);
        let en = (t(Msg::OriginDisk), t(Msg::OriginNew));
        set(Lang::Tr);
        assert_eq!(en, (t(Msg::OriginDisk), t(Msg::OriginNew)));
        set(Lang::En);
    }

    #[test]
    fn launcher_strings_switch_with_the_global_lang() {
        let _guard = lock_lang();
        set(Lang::En);
        assert!(launcher_install_ok().contains("installed and running"));
        assert!(launcher_install_failed("x").contains("could not be installed"));
        assert!(launcher_uninstall_ok().contains("was removed"));
        assert_eq!(t(Msg::MenuRunOnce), "Run once (this session only)");

        set(Lang::Tr);
        assert!(launcher_install_ok().contains("kuruldu ve çalışıyor"));
        assert!(launcher_install_failed("x").contains("kurulamadı"));
        assert!(launcher_uninstall_ok().contains("kaldırıldı"));
        assert_eq!(t(Msg::MenuRunOnce), "Bir kez çalıştır (yalnızca bu oturum)");

        set(Lang::En);
    }

    #[test]
    fn tui_help_uses_arrow_glyphs_in_both_langs() {
        let _guard = lock_lang();
        set(Lang::En);
        assert!(t(Msg::TuiHelp).contains('\u{2191}') && t(Msg::TuiHelp).contains("quit"));
        set(Lang::Tr);
        assert!(t(Msg::TuiHelp).contains('\u{2191}') && t(Msg::TuiHelp).contains("çık"));
        set(Lang::En);
    }
}
