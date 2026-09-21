// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of the client half of snowflake/v2 common/amp.

//! AMP cache rendezvous encoding: request paths, cache URLs and the HTML
//! armor the broker wraps answers in.

use std::io;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

/// Largest HTML token the decoder accepts (Go's `elementSizeLimit`).
const ELEMENT_SIZE_LIMIT: usize = 32 * 1024;

/// `amp.EncodePath`: "0" + b64url(9 random bytes) + "/" + b64url(data).
pub fn encode_path(data: &[u8]) -> String {
    let mut breaker = [0u8; 9];
    crate::shared::domain::crypto::csrand::bytes(&mut breaker);
    format!(
        "0{}/{}",
        URL_SAFE_NO_PAD.encode(breaker),
        URL_SAFE_NO_PAD.encode(data)
    )
}

fn base32_lower_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn domain_prefix_basic(domain: &str) -> Option<String> {
    let (unicode, res) = idna::domain_to_unicode(domain);
    res.ok()?;
    let mut prefix = unicode.replace('-', "--").replace('.', "-");
    let b = prefix.as_bytes();
    if b.len() >= 4 && b[2] == b'-' && b[3] == b'-' {
        prefix = format!("0-{prefix}-0");
    }
    if prefix.is_ascii() {
        Some(prefix)
    } else {
        idna::domain_to_ascii(&prefix).ok()
    }
}

/// AMP cache subdomain for `domain` (with the SHA-256 fallback).
pub fn domain_prefix(domain: &str) -> String {
    match domain_prefix_basic(domain) {
        Some(p) if p.len() <= 63 => p,
        _ => base32_lower_nopad(&Sha256::digest(domain.as_bytes())),
    }
}

/// `path.Join` for absolute or relative slash paths.
fn path_join(parts: &[&str]) -> String {
    let joined = parts
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return String::new();
    }
    let rooted = joined.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|s| *s != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let body = out.join("/");
    match (rooted, body.is_empty()) {
        (true, _) => format!("/{body}"),
        (false, true) => ".".into(),
        (false, false) => body,
    }
}

/// `amp.CacheURL(pub, cache, contentType)`.
pub fn cache_url(
    pub_url: &url::Url,
    cache: &url::Url,
    content_type: &str,
) -> Result<url::Url, String> {
    let pub_host = pub_url.host_str().unwrap_or_default();
    let pub_host = pub_host.trim_start_matches('[').trim_end_matches(']');
    let cache_host = cache.host_str().unwrap_or_default();
    let mut host = format!("{}.{}", domain_prefix(pub_host), cache_host);
    if let Some(p) = cache.port() {
        host = format!("{host}:{p}");
    }
    if content_type.is_empty() {
        return Err(format!("invalid content type {content_type:?}"));
    }
    let scheme_part = match pub_url.scheme() {
        "http" => "",
        "https" => "s",
        s => return Err(format!("invalid scheme {s:?} in publisher URL")),
    };
    if !pub_url.username().is_empty() || pub_url.password().is_some() {
        return Err("publisher URL may not contain userinfo".into());
    }
    // `url` drops default ports, so any port left is non-default.
    if let Some(p) = pub_url.port() {
        return Err(format!(
            "publisher URL port \"{p}\" is not the default for scheme \"{}\"",
            pub_url.scheme()
        ));
    }
    if pub_host.is_empty() {
        return Err(format!("invalid host {pub_host:?} in publisher URL"));
    }
    if cache.query().is_some_and(|q| !q.is_empty()) {
        return Err("cache URL may not contain a query".into());
    }
    if cache.fragment().is_some_and(|f| !f.is_empty()) {
        return Err("cache URL may not contain a fragment".into());
    }
    let host_seg = percent_encoding::utf8_percent_encode(pub_host, PATH_SEGMENT).to_string();
    let ct_seg = percent_encoding::utf8_percent_encode(content_type, PATH_SEGMENT).to_string();
    let path = path_join(&[
        cache.path(),
        &ct_seg,
        scheme_part,
        &host_seg,
        pub_url.path(),
    ]);
    let mut out = format!("{}://", cache.scheme());
    if !cache.username().is_empty() {
        out.push_str(cache.username());
        if let Some(pw) = cache.password() {
            out.push(':');
            out.push_str(pw);
        }
        out.push('@');
    }
    out.push_str(&host);
    out.push_str(&path);
    if let Some(q) = pub_url.query() {
        out.push('?');
        out.push_str(q);
    }
    if let Some(f) = pub_url.fragment() {
        out.push('#');
        out.push_str(f);
    }
    url::Url::parse(&out).map_err(|e| e.to_string())
}

/// Characters Go's `url.PathEscape` escapes.
const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b':')
    .remove(b'=')
    .remove(b'@');

const RAW_TEXT_TAGS: &[&str] = &[
    "iframe",
    "noembed",
    "noframes",
    "noscript",
    "plaintext",
    "script",
    "style",
    "textarea",
    "title",
    "xmp",
];

fn tag_name(b: &[u8]) -> String {
    b.iter()
        .take_while(|c| !c.is_ascii_whitespace() && **c != b'/' && **c != b'>')
        .map(|c| c.to_ascii_lowercase() as char)
        .collect()
}

/// Index just past the `>` closing the tag starting at `b[0] == '<'`,
/// honouring quoted attribute values.
fn tag_end(b: &[u8]) -> Option<usize> {
    let mut quote = None;
    for (i, &c) in b.iter().enumerate().skip(1) {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == b'"' || c == b'\'' => quote = Some(c),
            None if c == b'>' => return Some(i + 1),
            None => {}
        }
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Concatenated non-whitespace text of all `<pre>` elements.
fn pre_text(html: &[u8]) -> io::Result<Vec<u8>> {
    let err = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
    let mut out = Vec::new();
    let mut active = false;
    let mut i = 0;
    while i < html.len() {
        let rest = &html[i..];
        if rest[0] != b'<' {
            let end = rest.iter().position(|&c| c == b'<').unwrap_or(rest.len());
            if end > ELEMENT_SIZE_LIMIT {
                return Err(err("max buffer exceeded".into()));
            }
            if active {
                out.extend(
                    rest[..end]
                        .iter()
                        .filter(|c| !matches!(c, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')),
                );
            }
            i += end;
            continue;
        }
        if rest.starts_with(b"<!--") {
            i += find(&rest[4..], b"-->").map_or(rest.len(), |e| e + 7);
            continue;
        }
        let closing = rest.get(1) == Some(&b'/');
        let name_start = if closing { 2 } else { 1 };
        let is_tag = rest.get(name_start).is_some_and(u8::is_ascii_alphabetic);
        if rest.get(1).is_some_and(|c| *c == b'!' || *c == b'?') || (closing && !is_tag) {
            i += rest
                .iter()
                .position(|&c| c == b'>')
                .map_or(rest.len(), |e| e + 1);
            continue;
        }
        if !is_tag {
            if active {
                out.push(b'<');
            }
            i += 1;
            continue;
        }
        let name = tag_name(&rest[name_start..]);
        let end = tag_end(rest).unwrap_or(rest.len());
        if end > ELEMENT_SIZE_LIMIT {
            return Err(err("max buffer exceeded".into()));
        }
        i += end;
        if name == "pre" {
            if active != closing {
                let tok = String::from_utf8_lossy(&rest[..end]);
                return Err(err(format!("unexpected {tok}")));
            }
            active = !closing;
        } else if !closing && RAW_TEXT_TAGS.contains(&name.as_str()) {
            let close = format!("</{name}");
            i += find(&html[i..], close.as_bytes()).unwrap_or(html.len() - i);
        }
    }
    if active {
        return Err(err("missing </pre> tag".into()));
    }
    Ok(out)
}

/// `amp.NewArmorDecoder` read to the end.
pub fn armor_decode(html: &[u8]) -> io::Result<Vec<u8>> {
    let text = pre_text(html)?;
    match text.first() {
        None => Err(io::ErrorKind::UnexpectedEof.into()),
        Some(b'0') => STANDARD.decode(&text[1..]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("illegal base64 data: {e}"),
            )
        }),
        Some(&v) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown armor version indicator '{}'", v.escape_ascii()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_prefixes_match_upstream_tests() {
        // snowflake common/amp/cache_test.go (inputs as `url` normalizes them).
        for (domain, want) in [
            ("", ""),
            ("...", "---"),
            ("b\u{fc}cher.de", "xn--bcher-de-65a"),
            ("xn--bcher-kva.de", "xn--bcher-de-65a"),
            ("fa\u{df}.de", "xn--fa-de-mqa"),
            (
                "\u{3b2}\u{3cc}\u{3bb}\u{3bf}\u{3c3}.com",
                "xn---com-4ld8c2a6a8e",
            ),
            (&"a".repeat(64), &"a".repeat(64)),
            ("example.com", "example-com"),
            ("foo.example.com", "foo-example-com"),
            ("foo-example.com", "foo--example-com"),
            ("xn--57hw060o.com", "xn---com-p33b41770a"),
            ("\u{26a1}\u{1f60a}.com", "xn---com-p33b41770a"),
            ("en-us.example.com", "0-en--us-example-com-0"),
        ] {
            assert_eq!(
                domain_prefix_basic(domain).as_deref(),
                Some(want),
                "{domain}"
            );
        }
        for (domain, want) in [
            ("", "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq"),
            (
                "example.com",
                "un42n5xov642kxrxrqiyanhcoupgql5lt4wtbkyt2ijflbwodfdq",
            ),
            (
                "000000000000000000000000000000000000000000000000000000000000.com",
                "stejanx4hsijaoj4secyecy4nvqodk56kw72whwcmvdbtucibf5a",
            ),
            (
                "00000000000000000000000000000000000000000000000000000000000\u{3bb}.com",
                "qhzqeumjkfpcpuic3vqruyjswcr7y7gcm3crqyhhywvn3xrhchfa",
            ),
        ] {
            assert_eq!(
                base32_lower_nopad(&Sha256::digest(domain.as_bytes())),
                want,
                "{domain}"
            );
        }
        assert_eq!(domain_prefix(&"a".repeat(63)), "a".repeat(63));
        let long = "a".repeat(64);
        assert_eq!(
            domain_prefix(&long),
            base32_lower_nopad(&Sha256::digest(long.as_bytes()))
        );
    }

    #[test]
    fn cache_urls() {
        // snowflake common/amp/cache_test.go TestCacheURL.
        for (pub_url, cache, ct, want) in [
            (
                "http://example.com/",
                "https://amp.cache/",
                "c",
                "https://example-com.amp.cache/c/example.com",
            ),
            (
                "http://example.com",
                "https://amp.cache/",
                "c",
                "https://example-com.amp.cache/c/example.com",
            ),
            (
                "https://example.com/",
                "https://amp.cache/",
                "c",
                "https://example-com.amp.cache/c/s/example.com",
            ),
            (
                "http://example.com/",
                "https://amp.cache/",
                "/",
                "https://example-com.amp.cache/%2F/example.com",
            ),
            (
                "http://example.com/my%2Fpath/index.html?a=1#fragment",
                "https://amp.cache/",
                "c",
                "https://example-com.amp.cache/c/example.com/my%2Fpath/index.html?a=1#fragment",
            ),
            (
                "http://example.com:80/",
                "https://amp.cache/",
                "c",
                "https://example-com.amp.cache/c/example.com",
            ),
            (
                "https://example.com:443/",
                "https://amp.cache/",
                "c",
                "https://example-com.amp.cache/c/s/example.com",
            ),
            (
                "https://example.com/amp/client/0abc/def",
                "https://cdn.ampproject.org/",
                "c",
                "https://example-com.cdn.ampproject.org/c/s/example.com/amp/client/0abc/def",
            ),
        ] {
            let got = cache_url(
                &url::Url::parse(pub_url).unwrap(),
                &url::Url::parse(cache).unwrap(),
                ct,
            );
            assert_eq!(got.unwrap().as_str(), want, "{pub_url} {cache} {ct}");
        }
        let cache = url::Url::parse("https://amp.cache/").unwrap();
        for bad in [
            "https://example.com:444/",
            "http://example.com:443/",
            "ftp://example.com/",
            "https://u@example.com/",
        ] {
            assert!(
                cache_url(&url::Url::parse(bad).unwrap(), &cache, "c").is_err(),
                "{bad}"
            );
        }
        let pub_url = url::Url::parse("http://example.com/").unwrap();
        assert!(cache_url(&pub_url, &cache, "").is_err());
        assert!(cache_url(
            &pub_url,
            &url::Url::parse("https://amp.cache/?q").unwrap(),
            "c"
        )
        .is_err());
    }

    #[test]
    fn encodes_paths() {
        let p = encode_path(b"hello");
        assert_eq!(p.len(), 1 + 12 + 1 + 7);
        assert!(p.starts_with('0') && p.ends_with("/aGVsbG8"));
    }

    fn armor(data: &[u8]) -> String {
        // Mirrors armor_encoder.go: boilerplate, then `<pre>` elements.
        let enc = format!("0{}", STANDARD.encode(data));
        let mut s = String::from(
            "<!doctype html>\n<html amp>\n<head>\n<script async src=\"x.js\"></script>\n\
             <style amp-boilerplate>body{a:b}<pre>not this</pre></style><noscript><style amp-boilerplate>body{}</style></noscript>\n\
             </head>\n<body>\n",
        );
        for chunk in enc.as_bytes().chunks(40) {
            s.push_str("<pre>\n");
            for line in chunk.chunks(16) {
                s.push_str(std::str::from_utf8(line).unwrap());
                s.push('\n');
            }
            s.push_str("</pre>\n");
        }
        s.push_str("</body>\n</html>");
        s
    }

    #[test]
    fn decodes_armor() {
        for data in [
            &b""[..],
            b"x",
            b"hello, world, this is a longer message \x00\xff",
        ] {
            assert_eq!(armor_decode(armor(data).as_bytes()).unwrap(), data);
        }
        assert!(armor_decode(b"<pre>1abc</pre>").is_err());
        assert!(armor_decode(b"<pre>0aGk=").is_err());
        assert!(armor_decode(b"<pre><pre>0aGk=</pre>").is_err());
        assert!(armor_decode(b"<html>nothing</html>").is_err());
        assert_eq!(
            armor_decode(b"<PRE class='a>b'>0a<!-- x -->Gk=</PRE>").unwrap(),
            b"hi"
        );
    }
}
