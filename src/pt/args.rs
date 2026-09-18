// Port of goptlib args.go (CC0).

//! Key/value transport arguments and their pt-spec encodings.

use std::collections::{BTreeMap, HashMap};

/// Multi-valued args; iteration is key-sorted (as goptlib's encoder sorts).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Args(BTreeMap<String, Vec<String>>);

impl Args {
    pub fn new() -> Args {
        Args::default()
    }

    /// First value for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.first()).map(String::as_str)
    }

    pub fn add(&mut self, key: &str, value: &str) {
        self.0
            .entry(key.to_string())
            .or_default()
            .push(value.to_string());
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.0.iter()
    }
}

/// Scans to the first unescaped byte in `term`, unescaping along the way.
fn index_unescaped(s: &[u8], term: &[u8]) -> Result<(usize, String), String> {
    let mut unesc = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let mut b = s[i];
        if term.contains(&b) {
            break;
        }
        if b == b'\\' {
            i += 1;
            if i >= s.len() {
                return Err(format!(
                    "nothing following final escape in {:?}",
                    String::from_utf8_lossy(s)
                ));
            }
            b = s[i];
        }
        unesc.push(b);
        i += 1;
    }
    let text = String::from_utf8(unesc).map_err(|e| e.to_string())?;
    Ok((i, text))
}

/// `k=v;k=v` with backslash escapes (goptlib `parseClientParameters`).
pub fn parse_client_parameters(s: &str) -> Result<Args, String> {
    let mut args = Args::new();
    let s = s.as_bytes();
    if s.is_empty() {
        return Ok(args);
    }
    let mut i = 0;
    loop {
        let begin = i;
        let (off, key) = index_unescaped(&s[i..], b"=;")?;
        i += off;
        if i >= s.len() || s[i] != b'=' {
            return Err(format!(
                "no equals sign in {:?}",
                String::from_utf8_lossy(&s[begin..i])
            ));
        }
        i += 1;
        let (off, value) = index_unescaped(&s[i..], b";")?;
        i += off;
        if key.is_empty() {
            return Err(format!(
                "empty key in {:?}",
                String::from_utf8_lossy(&s[begin..i])
            ));
        }
        args.add(&key, &value);
        if i >= s.len() {
            break;
        }
        i += 1;
    }
    Ok(args)
}

/// `TOR_PT_SERVER_TRANSPORT_OPTIONS`: `method:k=v;method:k=v`.
pub fn parse_server_transport_options(s: &str) -> Result<HashMap<String, Args>, String> {
    let mut opts: HashMap<String, Args> = HashMap::new();
    let s = s.as_bytes();
    if s.is_empty() {
        return Ok(opts);
    }
    let mut i = 0;
    loop {
        let begin = i;
        let (off, method) = index_unescaped(&s[i..], b":=;")?;
        i += off;
        if i >= s.len() || s[i] != b':' {
            return Err(format!(
                "no colon in {:?}",
                String::from_utf8_lossy(&s[begin..i])
            ));
        }
        i += 1;
        let (off, key) = index_unescaped(&s[i..], b"=;")?;
        i += off;
        if i >= s.len() || s[i] != b'=' {
            return Err(format!(
                "no equals sign in {:?}",
                String::from_utf8_lossy(&s[begin..i])
            ));
        }
        i += 1;
        let (off, value) = index_unescaped(&s[i..], b";")?;
        i += off;
        let span = String::from_utf8_lossy(&s[begin..i]).into_owned();
        if method.is_empty() {
            return Err(format!("empty method name in {span:?}"));
        }
        if key.is_empty() {
            return Err(format!("empty key in {span:?}"));
        }
        opts.entry(method).or_default().add(&key, &value);
        if i >= s.len() {
            break;
        }
        i += 1;
    }
    Ok(opts)
}

fn backslash_escape(s: &str, set: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' || (c.is_ascii() && set.contains(&(c as u8))) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The value of an SMETHOD `ARGS:` option (without the prefix).
pub fn encode_smethod_args(args: Option<&Args>) -> String {
    let Some(args) = args else {
        return String::new();
    };
    let esc = |s: &str| backslash_escape(s, b"=,");
    let mut pairs = Vec::new();
    for (key, values) in args.iter() {
        for value in values {
            pairs.push(format!("{}={}", esc(key), esc(value)));
        }
    }
    pairs.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_parameters() {
        let a = parse_client_parameters(r"cert=abc\;d;iat-mode=0;k=\=\\").unwrap();
        assert_eq!(a.get("cert"), Some("abc;d"));
        assert_eq!(a.get("iat-mode"), Some("0"));
        assert_eq!(a.get("k"), Some(r"=\"));
        assert!(parse_client_parameters("novalue").is_err());
        assert!(parse_client_parameters("=v").is_err());
        assert!(parse_client_parameters(r"k=v\").is_err());
        assert_eq!(parse_client_parameters("").unwrap(), Args::new());
        // goptlib rejects a trailing ';' (the next key has no '=').
        assert!(parse_client_parameters("a=b;").is_err());
    }

    #[test]
    fn server_options() {
        let o = parse_server_transport_options(r"obfs4:iat-mode=1;obfs4:k=a\;b;x:y=z").unwrap();
        assert_eq!(o["obfs4"].get("iat-mode"), Some("1"));
        assert_eq!(o["obfs4"].get("k"), Some("a;b"));
        assert_eq!(o["x"].get("y"), Some("z"));
        assert!(parse_server_transport_options("obfs4=1").is_err());
        assert!(parse_server_transport_options(":k=v").is_err());
    }

    #[test]
    fn smethod_encoding_is_sorted_and_escaped() {
        let mut a = Args::new();
        a.add("iat-mode", "0");
        a.add("cert", "a=b,c");
        assert_eq!(encode_smethod_args(Some(&a)), r"cert=a\=b\,c,iat-mode=0");
        assert_eq!(encode_smethod_args(None), "");
    }
}
