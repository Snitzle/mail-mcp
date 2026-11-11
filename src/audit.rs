//! A record of everything the server changed or sent, and the send-rate limiter.
//!
//! Each event goes to two places: a private log file the user can read with `mail-mcp log`,
//! and the systemd journal. The journal copy matters because an unprivileged process can
//! add to the journal but cannot edit or delete what is already there, so it survives even
//! if something running as the user removes the file.
//!
//! Message bodies are never logged.

use std::collections::HashMap;
use std::fs;
#[cfg(not(test))]
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::config::{APP, Paths, Policy};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::sanitize::oneline;

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const KEPT_LOGS: u32 = 5;
#[cfg(not(test))]
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
const MAX_FIELD_CHARS: usize = 300;
const MAX_LIST_ITEMS: usize = 50;

#[derive(Debug)]
pub struct Audit {
    log: PathBuf,
}

impl Audit {
    pub fn new(paths: &Paths) -> Self {
        Self {
            log: paths.audit_log(),
        }
    }

    /// Record an event. Logging problems are reported on stderr and never fail the action
    /// that was just carried out.
    pub fn record(&self, action: &str, account: &str, details: Value) {
        let mut event = Map::new();
        event.insert(
            "ts".into(),
            json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        );
        event.insert("action".into(), json!(action));
        event.insert("account".into(), json!(account));
        if let Value::Object(fields) = details {
            for (key, value) in fields {
                event.insert(key, bounded(value));
            }
        }
        let line = Value::Object(event).to_string();

        // Unit tests must not write made-up events into the real system journal.
        #[cfg(not(test))]
        send_to_journal(&line);
        self.rotate_if_large();
        if let Err(e) = fsutil::append_private(&self.log, &line) {
            eprintln!("{APP}: could not write the audit log: {e}");
        }
    }

    fn rotate_if_large(&self) {
        let Ok(meta) = fs::metadata(&self.log) else {
            return;
        };
        if meta.len() <= MAX_LOG_BYTES {
            return;
        }
        let numbered = |n: u32| self.log.with_extension(format!("log.{n}"));
        for n in (1..KEPT_LOGS).rev() {
            let _ = fs::rename(numbered(n), numbered(n + 1));
        }
        let _ = fs::rename(&self.log, numbered(1));
    }

    /// The last `count` lines of the current log file.
    pub fn tail(&self, count: usize) -> Result<Vec<String>> {
        let text = match fs::read_to_string(&self.log) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(Error::Io {
                    context: format!("reading {}", self.log.display()),
                    source,
                });
            }
        };
        let lines: Vec<&str> = text.lines().collect();
        Ok(lines[lines.len().saturating_sub(count)..]
            .iter()
            .map(|l| (*l).to_owned())
            .collect())
    }
}

/// Keep log entries small and single-line whatever the caller passes in.
fn bounded(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(oneline(&s, MAX_FIELD_CHARS)),
        Value::Array(items) => {
            let extra = items.len().saturating_sub(MAX_LIST_ITEMS);
            let mut out: Vec<Value> = items
                .into_iter()
                .take(MAX_LIST_ITEMS)
                .map(bounded)
                .collect();
            if extra > 0 {
                out.push(json!(format!("(+{extra} more)")));
            }
            Value::Array(out)
        }
        other => other,
    }
}

/// Send one event to journald using its native datagram protocol. Best effort.
#[cfg(not(test))]
fn send_to_journal(line: &str) {
    // `line` is JSON produced by serde_json, so it contains no raw newlines; the simple
    // KEY=value form of the protocol is therefore safe to use.
    let payload = format!("PRIORITY=5\nSYSLOG_IDENTIFIER={APP}\nMESSAGE={line}\n");
    if let Ok(socket) = UnixDatagram::unbound() {
        let _ = socket.send_to(payload.as_bytes(), JOURNAL_SOCKET);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Limits how many messages each account may send per minute and per day.
///
/// Counts are kept in memory for the life of the server and mirrored to a file so they
/// carry across restarts. Deleting the file while the server runs changes nothing.
#[derive(Debug)]
pub struct SendLimiter {
    file: PathBuf,
    per_minute: u32,
    per_day: u32,
    /// Unix timestamps of recent sends, per account.
    sent: Mutex<HashMap<String, Vec<u64>>>,
}

const DAY_SECS: u64 = 86_400;

impl SendLimiter {
    pub fn load(paths: &Paths, policy: &Policy) -> Self {
        let file = paths.sends_file();
        let sent = fs::read_to_string(&file)
            .ok()
            .and_then(|text| serde_json::from_str::<HashMap<String, Vec<u64>>>(&text).ok())
            .unwrap_or_default();
        Self {
            file,
            per_minute: policy.per_minute,
            per_day: policy.per_day,
            sent: Mutex::new(sent),
        }
    }

    /// Count one send against the account's limits, or refuse. Call this immediately
    /// before handing the message to the mail server: attempts count, so a burst of
    /// failing sends cannot be used to probe without limit.
    pub fn reserve(&self, account: &str) -> Result<()> {
        self.reserve_at(account, now_secs())
    }

    fn reserve_at(&self, account: &str, now: u64) -> Result<()> {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let times = sent.entry(account.to_owned()).or_default();
        times.retain(|t| now.saturating_sub(*t) < DAY_SECS);
        let last_minute = times
            .iter()
            .filter(|t| now.saturating_sub(**t) < 60)
            .count();
        if last_minute >= self.per_minute as usize {
            return Err(Error::denied(format!(
                "Send limit reached for {account}: {} per minute. Wait a minute before sending more.",
                self.per_minute
            )));
        }
        if times.len() >= self.per_day as usize {
            return Err(Error::denied(format!(
                "Send limit reached for {account}: {} per 24 hours.",
                self.per_day
            )));
        }
        times.push(now);
        if let Ok(text) = serde_json::to_string(&*sent)
            && let Err(e) = fsutil::write_private_atomic(&self.file, text.as_bytes())
        {
            eprintln!("{APP}: could not save the send counter: {e}");
        }
        Ok(())
    }

    /// Would one more send be allowed right now? Used to fail early, before asking the
    /// user to approve something that could not be sent anyway.
    pub fn check(&self, account: &str) -> Result<()> {
        let now = now_secs();
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let times: Vec<u64> = sent
            .get(account)
            .map(|t| {
                t.iter()
                    .copied()
                    .filter(|t| now.saturating_sub(*t) < DAY_SECS)
                    .collect()
            })
            .unwrap_or_default();
        let last_minute = times
            .iter()
            .filter(|t| now.saturating_sub(**t) < 60)
            .count();
        if last_minute >= self.per_minute as usize || times.len() >= self.per_day as usize {
            return Err(Error::denied(format!(
                "Send limit reached for {account} ({} per minute, {} per 24 hours).",
                self.per_minute, self.per_day
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &std::path::Path) -> Paths {
        Paths {
            home: dir.to_path_buf(),
            config_file: dir.join("config.toml"),
            state_dir: dir.join("state"),
            attachments_dir: dir.join("attachments"),
        }
    }

    fn policy(per_minute: u32, per_day: u32) -> Policy {
        Policy {
            per_minute,
            per_day,
            attach_dirs: vec![],
            read_only: false,
            pinned_accounts: vec![],
        }
    }

    #[test]
    fn events_are_single_bounded_lines_without_bodies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit = Audit::new(&paths(dir.path()));
        audit.record(
            "send",
            "hotmail",
            json!({ "to": ["a@b.example"], "subject": "line one\nline two", "big": "x".repeat(5000) }),
        );
        let lines = audit.tail(10).expect("tail");
        assert_eq!(lines.len(), 1);
        let event: Value = serde_json::from_str(&lines[0]).expect("json");
        assert_eq!(event["action"], "send");
        assert_eq!(event["subject"], "line one line two");
        assert!(event["big"].as_str().expect("str").chars().count() <= MAX_FIELD_CHARS + 1);
    }

    #[test]
    fn per_minute_limit_applies_and_recovers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let limiter = SendLimiter::load(&paths(dir.path()), &policy(2, 100));
        assert!(limiter.reserve_at("a", 1_000).is_ok());
        assert!(limiter.reserve_at("a", 1_001).is_ok());
        assert!(limiter.reserve_at("a", 1_002).is_err());
        // Another account has its own allowance.
        assert!(limiter.reserve_at("b", 1_002).is_ok());
        // A minute later the first account may send again.
        assert!(limiter.reserve_at("a", 1_061).is_ok());
    }

    #[test]
    fn per_day_limit_applies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let limiter = SendLimiter::load(&paths(dir.path()), &policy(100, 3));
        for i in 0..3 {
            assert!(limiter.reserve_at("a", 1_000 + i * 120).is_ok());
        }
        assert!(limiter.reserve_at("a", 2_000).is_err());
        assert!(limiter.reserve_at("a", 1_000 + DAY_SECS + 1).is_ok());
    }

    #[test]
    fn counts_survive_restart_and_ignore_file_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = paths(dir.path());
        let now = now_secs();
        let first = SendLimiter::load(&p, &policy(1, 100));
        assert!(first.reserve_at("a", now).is_ok());

        // A new server process sees the earlier send.
        let second = SendLimiter::load(&p, &policy(1, 100));
        assert!(second.reserve_at("a", now + 1).is_err());

        // Removing the file does not reset a running server.
        fs::remove_file(p.sends_file()).expect("remove");
        assert!(first.reserve_at("a", now + 2).is_err());
    }
}
