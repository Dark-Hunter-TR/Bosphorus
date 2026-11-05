//! Tracing subscriber setup. Interactive runs log to the console (as before);
//! the service logs to a rolling daily file under `%ProgramData%\Bosphorus\logs`
//! and mirrors ERROR / `bosphorus::net` / grid-EXHAUSTED events to the Windows
//! Event Log.
//!
//! Console output is always plain text. `tracing-subscriber` writes ANSI colour
//! escapes whenever the `ansi` feature is compiled in, and a Windows console --
//! or any redirected output -- prints them literally (`[0m`, `[32m`, ...). Every
//! console sink therefore goes through [`console_layer`], which disables them.
//! The service's file layer already did.

use std::path::{Path, PathBuf};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub enum LogSink {
    /// Interactive console (used once `run_engine` is switched over in 4c).
    #[allow(dead_code)]
    Console,
    ServiceFile { dir: PathBuf },
}

/// The console formatter: target-tagged, and **never** ANSI.
///
/// A function rather than a builder expression repeated at each call site, so the
/// ANSI policy is decided once and a test can render events through exactly the
/// configuration production uses.
pub fn console_layer<S, W>(writer: W) -> impl Layer<S>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(writer)
}

/// Install the interactive console subscriber: `RUST_LOG` if set, else
/// `default_filter`, with ANSI escapes disabled.
pub fn init_console(default_filter: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer(std::io::stdout))
        .try_init();
}

/// Install the global subscriber. For the service, returns a guard that must be
/// held for the lifetime of the process (flushes the non-blocking file writer).
pub fn init(sink: LogSink) -> Option<WorkerGuard> {
    match sink {
        LogSink::Console => {
            init_console("info");
            None
        }
        LogSink::ServiceFile { dir } => {
            let _ = std::fs::create_dir_all(&dir);
            prune_old_logs(&dir, 14);

            let (writer, guard) =
                tracing_appender::non_blocking(tracing_appender::rolling::daily(&dir, "bosphorus.log"));
            let filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("bosphorus=info,warn"));
            let file_layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(writer);

            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(file_layer)
                .with(EventLogLayer)
                .try_init();
            Some(guard)
        }
    }
}

fn prune_old_logs(dir: &Path, keep_days: u64) {
    let Some(cutoff) =
        std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(keep_days * 86_400))
    else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("bosphorus.log") {
            continue;
        }
        if let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) {
            if mtime < cutoff {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Forwards a small, high-signal subset of events to the Windows Event Log.
struct EventLogLayer;

struct MsgVisitor(String);
impl Visit for MsgVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: Subscriber> Layer<S> for EventLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let (target, level) = (meta.target(), *meta.level());

        let is_net = target == "bosphorus::net";
        let is_exhausted = target == "bosphorus::discovery" && level == Level::WARN;
        if level != Level::ERROR && !is_net && !is_exhausted {
            return;
        }

        let mut v = MsgVisitor(String::new());
        event.record(&mut v);
        let msg = if v.0.is_empty() { target.to_string() } else { v.0 };

        let id = if is_net {
            crate::eventlog::ID_NET_CHANGED
        } else if is_exhausted {
            crate::eventlog::ID_GRID_EXHAUSTED
        } else {
            1
        };
        match level {
            Level::ERROR => crate::eventlog::error(id, &msg),
            Level::WARN => crate::eventlog::warn(id, &msg),
            _ => crate::eventlog::info(id, &msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A `MakeWriter` that keeps everything the subscriber emits.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8 log output")
        }
    }

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Regression: console logs used `tracing_subscriber::fmt()` with the default
    /// (ANSI-enabled) formatter, so a Windows console — or any redirected output —
    /// showed the escapes literally instead of ignoring them.
    #[test]
    fn console_output_contains_no_ansi_escapes() {
        let sink = Captured::default();
        let subscriber = tracing_subscriber::registry().with(console_layer(sink.clone()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "bosphorus::discovery", key = "example.com", tried = 3, "info");
            tracing::warn!(target: "bosphorus::net", "warn");
            tracing::error!(target: "bosphorus::engine", "error");
        });

        let text = sink.text();
        // The messages still reach the console...
        for expected in ["info", "warn", "error", "example.com"] {
            assert!(text.contains(expected), "missing {expected:?} in {text:?}");
        }
        // ...without any escape sequence.
        assert!(
            !text.contains('\u{1b}'),
            "ANSI escape emitted to the console: {text:?}"
        );
        for code in ["[0m", "[32m", "[31m", "[1m"] {
            assert!(
                !text.contains(code),
                "literal ANSI code {code:?} in console output: {text:?}"
            );
        }
    }

    /// The target tag is part of the console format and must survive with ANSI
    /// off: it is what distinguishes `bosphorus::discovery` from `bosphorus::net`.
    #[test]
    fn console_output_keeps_the_target_tag() {
        let sink = Captured::default();
        let subscriber = tracing_subscriber::registry().with(console_layer(sink.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "bosphorus::discovery", "tagged");
        });
        assert!(
            sink.text().contains("bosphorus::discovery"),
            "{}",
            sink.text()
        );
    }
}
