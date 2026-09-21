//! Dependency rules of the hexagonal layout, checked on the source text:
//!
//! - `domain` and `ports` do no I/O of their own: no adapters, no sockets,
//!   files, environment, stdio, signals, TLS or WebRTC stacks.
//! - `app` reaches the outside world only through ports.
//! - `shared` does not know about the application or any transport.
//! - A transport never reaches into another transport.
//!
//! Test modules (`#[cfg(test)]` at the end of a file) are exempt: tests may
//! wire real adapters.

use std::path::{Path, PathBuf};

/// Code that does I/O itself, or names a concrete I/O stack.
const IO: &[&str] = &[
    "adapters::",
    "crate::app",
    "tokio::net",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "std::fs",
    "std::env",
    "std::process",
    "std::io::stdout",
    "std::io::stdin",
    "println!",
    "eprintln!",
    "tokio::signal",
    "rustls::",
    "tokio_rustls::",
    "webpki_roots::",
    "str0m::",
];

const TRANSPORTS: &[&str] = &["obfs4", "snowflake", "webtunnel"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Non-test code of `path`, comments dropped.
fn production_code(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn violations() -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut found = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let parts: Vec<&str> = rel.split('/').collect();
        let code = production_code(&path);
        let mut forbid = |pattern: &str, rule: &str| {
            if code.contains(pattern) {
                found.push(format!("{rel}: `{pattern}` ({rule})"));
            }
        };

        if parts.contains(&"domain") || parts.contains(&"ports") {
            for p in IO {
                forbid(p, "domain and ports do no I/O");
            }
        }
        if parts[0] == "app" {
            forbid("adapters::", "the application uses ports, not adapters");
        }
        if parts[0] == "shared" {
            forbid("crate::app", "shared code does not know the application");
            forbid(
                "crate::transports",
                "shared code does not know the transports",
            );
        }
        if parts[0] == "transports" && parts.len() > 2 {
            let own = parts[1];
            forbid("crate::app", "transports do not know the application");
            for other in TRANSPORTS.iter().filter(|t| **t != own) {
                forbid(
                    &format!("transports::{other}"),
                    "transports are independent of each other",
                );
            }
        }
    }
    found
}

#[test]
fn layers_depend_inwards() {
    let found = violations();
    assert!(found.is_empty(), "\n{}", found.join("\n"));
}

#[test]
fn every_transport_is_a_hexagon() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for t in TRANSPORTS {
        for layer in ["domain", "ports", "adapters"] {
            let dir = src.join("transports").join(t).join(layer);
            assert!(dir.join("mod.rs").is_file(), "missing {}", dir.display());
        }
    }
    for layer in ["domain", "ports", "adapters"] {
        assert!(src.join("shared").join(layer).join("mod.rs").is_file());
    }
}
