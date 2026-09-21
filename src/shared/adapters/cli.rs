// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of the flags of lyrebird cmd/lyrebird.

//! Command-line flags, in Go `flag` package syntax.

pub struct Flags {
    pub show_version: bool,
    pub log_level: String,
    pub enable_logging: bool,
    pub unsafe_logging: bool,
    pub dist_bias: bool,
}

pub const USAGE: &str = "Usage of lyrebird:
  -enableLogging
    \tLog to TOR_PT_STATE_LOCATION/lyrebird.log
  -logLevel string
    \tLog level (ERROR/WARN/INFO/DEBUG) (default \"ERROR\")
  -obfs4-distBias
    \tEnable obfs4 using ScrambleSuit style table generation
  -unsafeLogging
    \tDisable the address scrubber
  -version
    \tPrint version and exit";

fn parse_bool(name: &str, v: &str) -> Result<bool, String> {
    match v {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(format!(
            "invalid boolean value {v:?} for -{name}: parse error"
        )),
    }
}

/// Go `flag` package syntax: `-name`, `--name`, `-name=value`, `-name value`.
/// `Err("")` is a request for help.
pub fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut f = Flags {
        show_version: false,
        log_level: "ERROR".into(),
        enable_logging: false,
        unsafe_logging: false,
        dist_bias: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" || !arg.starts_with('-') || arg == "-" {
            break;
        }
        let body = arg.trim_start_matches('-');
        if arg.len() - body.len() > 2 || body.is_empty() || body.starts_with('=') {
            return Err(format!("bad flag syntax: {arg}"));
        }
        let (name, value) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (body, None),
        };
        match name {
            "version" | "enableLogging" | "unsafeLogging" | "obfs4-distBias" => {
                let v = match &value {
                    Some(v) => parse_bool(name, v)?,
                    None => true,
                };
                match name {
                    "version" => f.show_version = v,
                    "enableLogging" => f.enable_logging = v,
                    "unsafeLogging" => f.unsafe_logging = v,
                    _ => f.dist_bias = v,
                }
            }
            "logLevel" => {
                f.log_level = match value {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| format!("flag needs an argument: -{name}"))?
                    }
                };
            }
            "h" | "help" => return Err(String::new()),
            _ => return Err(format!("flag provided but not defined: -{name}")),
        }
        i += 1;
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn go_flag_syntax() {
        let f = parse_flags(&v(&[
            "-enableLogging",
            "--logLevel",
            "DEBUG",
            "-unsafeLogging=false",
        ]))
        .unwrap();
        assert!(f.enable_logging);
        assert_eq!(f.log_level, "DEBUG");
        assert!(!f.unsafe_logging);
        let f = parse_flags(&v(&["-logLevel=INFO", "-obfs4-distBias"])).unwrap();
        assert_eq!(f.log_level, "INFO");
        assert!(f.dist_bias);
        assert!(parse_flags(&v(&["-nope"])).is_err());
        assert!(parse_flags(&v(&["-logLevel"])).is_err());
        assert!(parse_flags(&v(&["---version"])).is_err());
        assert!(parse_flags(&v(&["-version=maybe"])).is_err());
        // Parsing stops at the first non-flag argument.
        assert!(parse_flags(&v(&["positional", "-nope"])).is_ok());
    }
}
