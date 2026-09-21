// Port of goptlib pt.go (CC0) — the Tor pluggable transport spec, v1.

//! Control lines to tor (`VERSION`, `CMETHOD`, `SMETHOD`, `STATUS`, `LOG`,
//! `PROXY` and their `-ERROR` forms), written through `ControlOutput`.

use std::net::SocketAddr;
use std::sync::Arc;

use super::args::{self, Args};
use crate::shared::ports::control::ControlOutput;

/// Error already reported to tor (as `ENV-ERROR` etc.) where applicable.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PtError(pub String);

#[derive(Clone, Copy)]
pub enum LogSeverity {
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

fn keyword_is_safe(k: &str) -> bool {
    k.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn arg_is_safe(a: &str) -> bool {
    a.bytes().all(|b| b < 0x80 && b != 0 && b != b'\n')
}

fn format_line(keyword: &str, args: &[&str]) -> String {
    assert!(
        keyword_is_safe(keyword),
        "keyword {keyword:?} contains forbidden bytes"
    );
    let mut line = keyword.to_string();
    for a in args {
        assert!(arg_is_safe(a), "arg {a:?} contains forbidden bytes");
        line.push(' ');
        line.push_str(a);
    }
    line
}

/// C-style quoted string with octal escapes (pt-spec §3.3.4).
pub fn encode_cstring(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.bytes() {
        if c == 32 || c == 33 || (35..=91).contains(&c) || (93..=126).contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("\\{c:03o}"));
        }
    }
    out.push('"');
    out
}

/// The control channel to tor.
#[derive(Clone)]
pub struct TorControl(Arc<dyn ControlOutput>);

impl TorControl {
    pub fn new(out: Arc<dyn ControlOutput>) -> TorControl {
        TorControl(out)
    }

    /// Writes one control line.
    pub fn line(&self, keyword: &str, args: &[&str]) {
        self.0.write_line(&format_line(keyword, args));
    }

    fn error(&self, keyword: &str, args: &[&str]) -> PtError {
        self.line(keyword, args);
        PtError(format_line(keyword, args))
    }

    pub fn env_error(&self, msg: &str) -> PtError {
        self.error("ENV-ERROR", &[msg])
    }

    pub fn version_error(&self, msg: &str) -> PtError {
        self.error("VERSION-ERROR", &[msg])
    }

    pub fn cmethod_error(&self, method: &str, msg: &str) -> PtError {
        self.error("CMETHOD-ERROR", &[method, msg])
    }

    pub fn smethod_error(&self, method: &str, msg: &str) -> PtError {
        self.error("SMETHOD-ERROR", &[method, msg])
    }

    pub fn proxy_error(&self, msg: &str) -> PtError {
        self.error("PROXY-ERROR", &[msg])
    }

    pub fn cmethod(&self, name: &str, socks: &str, addr: &SocketAddr) {
        self.line("CMETHOD", &[name, socks, &addr.to_string()]);
    }

    pub fn cmethods_done(&self) {
        self.line("CMETHODS", &["DONE"]);
    }

    pub fn smethod_args(&self, name: &str, addr: &SocketAddr, args: Option<&Args>) {
        let encoded = format!("ARGS:{}", args::encode_smethod_args(args));
        self.line("SMETHOD", &[name, &addr.to_string(), &encoded]);
    }

    pub fn smethods_done(&self) {
        self.line("SMETHODS", &["DONE"]);
    }

    pub fn proxy_done(&self) {
        self.line("PROXY", &["DONE"]);
    }

    pub fn report_version(&self, implementation: &str, version: &str) {
        let imp = format!("IMPLEMENTATION={}", encode_cstring(implementation));
        let ver = format!("VERSION={}", encode_cstring(version));
        self.line("STATUS", &["TYPE=version", &imp, &ver]);
    }

    /// A `LOG` line: transport status for tor's own log.
    pub fn log(&self, severity: LogSeverity, message: &str) {
        let sev = match severity {
            LogSeverity::Error => "error",
            LogSeverity::Warning => "warning",
            LogSeverity::Notice => "notice",
            LogSeverity::Info => "info",
            LogSeverity::Debug => "debug",
        };
        let sev = format!("SEVERITY={sev}");
        let msg = format!("MESSAGE={}", encode_cstring(message));
        self.line("LOG", &[&sev, &msg]);
    }

    /// A channel that records its lines instead of sending them (tests).
    #[cfg(test)]
    pub fn capture() -> (TorControl, Arc<std::sync::Mutex<Vec<String>>>) {
        struct Capture(Arc<std::sync::Mutex<Vec<String>>>);
        impl ControlOutput for Capture {
            fn write_line(&self, line: &str) {
                self.0.lock().unwrap().push(line.to_string());
            }
        }
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        (TorControl::new(Arc::new(Capture(lines.clone()))), lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstring_escapes() {
        assert_eq!(encode_cstring("lyrebird"), "\"lyrebird\"");
        assert_eq!(encode_cstring("a\"b\\c\n"), "\"a\\042b\\134c\\012\"");
    }

    #[test]
    fn errors_are_sent_and_returned() {
        let (tor, lines) = TorControl::capture();
        let e = tor.cmethod_error("obfs4", "no such transport is supported");
        assert_eq!(
            e.to_string(),
            "CMETHOD-ERROR obfs4 no such transport is supported"
        );
        tor.log(LogSeverity::Notice, "a \"b\"");
        assert_eq!(
            *lines.lock().unwrap(),
            [
                "CMETHOD-ERROR obfs4 no such transport is supported",
                "LOG SEVERITY=notice MESSAGE=\"a \\042b\\042\""
            ]
        );
    }
}
