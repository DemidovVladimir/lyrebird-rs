// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of the address scrubber in lyrebird common/log and ptutil safelog.

//! Address scrubbing for anything that leaves the process as text.

pub const ELIDED_ADDR: &str = "[scrubbed]";

/// Replaces IP addresses (with or without port) in `s` (ptutil safelog).
pub fn scrub(s: &str) -> String {
    fn is_addr(token: &str) -> bool {
        let bare = token.trim_start_matches('[').trim_end_matches(']');
        token.parse::<std::net::SocketAddr>().is_ok()
            || bare.parse::<std::net::IpAddr>().is_ok()
            || token.parse::<std::net::Ipv4Addr>().is_ok()
    }
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        // Trailing ':' or '.' belong to the surrounding text.
        let core = token.trim_end_matches([':', '.']);
        if !core.is_empty() && core.contains(['.', ':']) && is_addr(core) {
            out.push_str(ELIDED_ADDR);
            out.push_str(&token[core.len()..]);
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in s.chars() {
        if c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '[' | ']') {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_addresses_in_text() {
        assert_eq!(scrub("dial 192.0.2.1:443 failed"), "dial [scrubbed] failed");
        assert_eq!(scrub("to [2001:db8::1]:80 x"), "to [scrubbed] x");
        assert_eq!(scrub("c=IN IP4 203.0.113.9\r\n"), "c=IN IP4 [scrubbed]\r\n");
        assert_eq!(scrub("at 10.0.0.1."), "at [scrubbed].");
        assert_eq!(
            scrub("no addr, code 404, v1.2, fe80::1"),
            "no addr, code 404, v1.2, [scrubbed]"
        );
        assert_eq!(
            scrub("a=fingerprint:sha-256 AB:CD:EF"),
            "a=fingerprint:sha-256 AB:CD:EF"
        );
    }
}
