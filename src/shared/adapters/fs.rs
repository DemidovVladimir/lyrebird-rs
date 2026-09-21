// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/log (the file) and goptlib's MakeStateDir.

//! The state directory and `lyrebird.log` on the local filesystem.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::shared::ports::log::LogSink;
use crate::shared::ports::storage::Storage;

pub struct FsStorage;

impl Storage for FsStorage {
    fn create_private_dir(&self, dir: &Path) -> io::Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)
    }

    fn open_log(&self, path: &Path) -> io::Result<Box<dyn LogSink>> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        Ok(Box::new(FileLog(Mutex::new(opts.open(path)?))))
    }
}

/// Lines prefixed with the local date and time (Go's `log.LstdFlags`).
struct FileLog(Mutex<File>);

impl LogSink for FileLog {
    fn write(&self, tag: Option<&str>, msg: &str) {
        let ts = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
        let mut f = self.0.lock().unwrap();
        let _ = match tag {
            Some(tag) => writeln!(f, "{ts} [{tag}]: {msg}"),
            None => {
                let nl = if msg.ends_with('\n') { "" } else { "\n" };
                write!(f, "{ts} {msg}{nl}")
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_lines_like_go() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("a/b");
        FsStorage.create_private_dir(&state).unwrap();
        let path = state.join("lyrebird.log");
        let log = FsStorage.open_log(&path).unwrap();
        log.write(Some("NOTICE"), "launched");
        log.write(None, "print\n");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].ends_with(" [NOTICE]: launched"), "{text}");
        assert!(
            lines[1].ends_with(" print") && !lines[1].contains('['),
            "{text}"
        );
        assert_eq!(lines.len(), 2);
    }
}
