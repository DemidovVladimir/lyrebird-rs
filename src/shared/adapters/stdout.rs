// Port of goptlib pt.go (CC0).

//! The pt-spec control channel on stdout.

use std::io::Write;
use std::sync::Mutex;

use crate::shared::ports::control::ControlOutput;

static STDOUT: Mutex<()> = Mutex::new(());

pub struct StdoutControl;

impl ControlOutput for StdoutControl {
    fn write_line(&self, line: &str) {
        let _guard = STDOUT.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}
