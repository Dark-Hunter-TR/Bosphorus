//! Tracing subscriber setup. Interactive runs log to the console (as before);
//! the service logs to a rolling daily file under `%ProgramData%\Bosphorus\logs`
//! and mirrors ERROR / `bosphorus::net` / grid-EXHAUSTED events to the Windows
//! Event Log.

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

/// Install the global subscriber. For the service, returns a guard that must be
/// held for the lifetime of the process (flushes the non-blocking file writer).
pub fn init(sink: LogSink) -> Option<WorkerGuard> {
    match sink {
        LogSink::Console => {
            let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(true).try_init();
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
