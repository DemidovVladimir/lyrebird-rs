// Port of goptlib pt.go (CC0) — the Tor pluggable transport spec, v1 — and
// of lyrebird cmd/lyrebird's managed-transport checks.

//! Managed-transport setup: version negotiation and the `TOR_PT_*`
//! environment, with errors reported to tor as they are found.

use std::net::SocketAddr;
use std::path::PathBuf;

use super::addr::resolve_addr;
use super::args::{self, Args};
use super::control::{PtError, TorControl};
use crate::shared::ports::env::Env;
use crate::shared::ports::storage::Storage;

fn getenv_required(env: &dyn Env, tor: &TorControl, key: &str) -> Result<String, PtError> {
    let v = env.var(key);
    if v.is_empty() {
        return Err(tor.env_error(&format!("no {key} environment variable")));
    }
    Ok(v)
}

fn get_managed_transport_ver(env: &dyn Env, tor: &TorControl) -> Result<String, PtError> {
    const TRANSPORT_VERSION: &str = "1";
    let offered = getenv_required(env, tor, "TOR_PT_MANAGED_TRANSPORT_VER")?;
    if offered.split(',').any(|v| v == TRANSPORT_VERSION) {
        Ok(TRANSPORT_VERSION.to_string())
    } else {
        Err(tor.version_error("no-version"))
    }
}

/// lyrebird's `ptIsClient`: which side tor launched us as.
pub fn is_client(env: &dyn Env, tor: &TorControl) -> Result<bool, String> {
    let client = env.var("TOR_PT_CLIENT_TRANSPORTS");
    let server = env.var("TOR_PT_SERVER_TRANSPORTS");
    match (client.is_empty(), server.is_empty()) {
        (false, false) => {
            tor.env_error("TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set");
            Err("TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set".into())
        }
        (false, true) => Ok(true),
        (true, false) => Ok(false),
        (true, true) => Err("not launched as a managed transport".into()),
    }
}

/// `TOR_PT_EXIT_ON_STDIN_CLOSE=1`: tor closes our stdin to stop us.
pub fn exit_on_stdin_close(env: &dyn Env) -> bool {
    env.var("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1"
}

/// `TOR_PT_STATE_LOCATION`, created with mode 0700.
pub fn make_state_dir(
    env: &dyn Env,
    tor: &TorControl,
    storage: &dyn Storage,
) -> Result<PathBuf, PtError> {
    let dir = PathBuf::from(getenv_required(env, tor, "TOR_PT_STATE_LOCATION")?);
    storage
        .create_private_dir(&dir)
        .map_err(|e| PtError(format!("mkdir {}: {e}", dir.display())))?;
    Ok(dir)
}

pub struct ClientInfo {
    pub method_names: Vec<String>,
}

/// Version negotiation and `TOR_PT_CLIENT_TRANSPORTS`. `TOR_PT_PROXY` is
/// validated by `proxy::from_env` (lyrebird's stricter check).
pub fn client_setup(env: &dyn Env, tor: &TorControl) -> Result<ClientInfo, PtError> {
    let ver = get_managed_transport_ver(env, tor)?;
    tor.line("VERSION", &[&ver]);
    let transports = getenv_required(env, tor, "TOR_PT_CLIENT_TRANSPORTS")?;
    Ok(ClientInfo {
        method_names: transports.split(',').map(str::to_string).collect(),
    })
}

#[derive(Clone, Debug)]
pub struct Bindaddr {
    pub method_name: String,
    pub addr: SocketAddr,
    pub options: Args,
}

pub struct ServerInfo {
    pub bindaddrs: Vec<Bindaddr>,
    pub or_addr: Option<SocketAddr>,
    pub extended_or_addr: Option<SocketAddr>,
    pub auth_cookie_path: String,
}

fn get_server_bindaddrs(env: &dyn Env, tor: &TorControl) -> Result<Vec<Bindaddr>, PtError> {
    let raw_opts = env.var("TOR_PT_SERVER_TRANSPORT_OPTIONS");
    let opts = args::parse_server_transport_options(&raw_opts).map_err(|e| {
        tor.env_error(&format!(
            "TOR_PT_SERVER_TRANSPORT_OPTIONS: {raw_opts:?}: {e}"
        ))
    })?;
    let bind = getenv_required(env, tor, "TOR_PT_SERVER_BINDADDR")?;
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for spec in bind.split(',') {
        let Some((name, addr)) = spec.split_once('-') else {
            return Err(tor.env_error(&format!(
                "TOR_PT_SERVER_BINDADDR: {spec:?}: doesn't contain \"-\""
            )));
        };
        if !seen.insert(name.to_string()) {
            return Err(tor.env_error(&format!(
                "TOR_PT_SERVER_BINDADDR: {spec:?}: duplicate method name {name:?}"
            )));
        }
        let addr = resolve_addr(addr)
            .map_err(|e| tor.env_error(&format!("TOR_PT_SERVER_BINDADDR: {spec:?}: {e}")))?;
        result.push(Bindaddr {
            method_name: name.to_string(),
            addr,
            options: opts.get(name).cloned().unwrap_or_default(),
        });
    }
    let transports = getenv_required(env, tor, "TOR_PT_SERVER_TRANSPORTS")?;
    let wanted: Vec<&str> = transports.split(',').collect();
    result.retain(|b| wanted.contains(&b.method_name.as_str()));
    Ok(result)
}

pub fn server_setup(env: &dyn Env, tor: &TorControl) -> Result<ServerInfo, PtError> {
    let ver = get_managed_transport_ver(env, tor)?;
    tor.line("VERSION", &[&ver]);
    let bindaddrs = get_server_bindaddrs(env, tor)?;

    let or_port = env.var("TOR_PT_ORPORT");
    let or_addr = if or_port.is_empty() {
        None
    } else {
        Some(resolve_addr(&or_port).map_err(|e| {
            tor.env_error(&format!("cannot resolve TOR_PT_ORPORT {or_port:?}: {e}"))
        })?)
    };

    let auth_cookie_path = env.var("TOR_PT_AUTH_COOKIE_FILE");
    let ext = env.var("TOR_PT_EXTENDED_SERVER_PORT");
    let extended_or_addr = if ext.is_empty() {
        None
    } else {
        if auth_cookie_path.is_empty() {
            return Err(tor.env_error(
                "need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT",
            ));
        }
        Some(resolve_addr(&ext).map_err(|e| {
            tor.env_error(&format!(
                "cannot resolve TOR_PT_EXTENDED_SERVER_PORT {ext:?}: {e}"
            ))
        })?)
    };
    if or_addr.is_none() && extended_or_addr.is_none() {
        return Err(
            tor.env_error("need TOR_PT_ORPORT or TOR_PT_EXTENDED_SERVER_PORT environment variable")
        );
    }
    Ok(ServerInfo {
        bindaddrs,
        or_addr,
        extended_or_addr,
        auth_cookie_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapEnv(HashMap<&'static str, &'static str>);

    impl Env for MapEnv {
        fn var(&self, key: &str) -> String {
            self.0.get(key).copied().unwrap_or_default().to_string()
        }
    }

    #[test]
    fn client_setup_reports_in_order() {
        let (tor, lines) = TorControl::capture();
        let env = MapEnv(HashMap::from([("TOR_PT_MANAGED_TRANSPORT_VER", "2,1")]));
        assert!(client_setup(&env, &tor).is_err());
        assert_eq!(
            *lines.lock().unwrap(),
            [
                "VERSION 1",
                "ENV-ERROR no TOR_PT_CLIENT_TRANSPORTS environment variable"
            ]
        );
        let env = MapEnv(HashMap::from([
            ("TOR_PT_MANAGED_TRANSPORT_VER", "1"),
            ("TOR_PT_CLIENT_TRANSPORTS", "obfs4,snowflake"),
        ]));
        let info = client_setup(&env, &tor).unwrap();
        assert_eq!(info.method_names, ["obfs4", "snowflake"]);
    }

    #[test]
    fn server_setup_filters_and_validates() {
        let (tor, lines) = TorControl::capture();
        let env = MapEnv(HashMap::from([
            ("TOR_PT_MANAGED_TRANSPORT_VER", "1"),
            ("TOR_PT_SERVER_BINDADDR", "obfs4-127.0.0.1:0,meek-[::1]:1"),
            ("TOR_PT_SERVER_TRANSPORTS", "obfs4"),
            ("TOR_PT_SERVER_TRANSPORT_OPTIONS", "obfs4:iat-mode=1"),
            ("TOR_PT_ORPORT", "127.0.0.1:9001"),
        ]));
        let info = server_setup(&env, &tor).unwrap();
        assert_eq!(info.bindaddrs.len(), 1);
        assert_eq!(info.bindaddrs[0].options.get("iat-mode"), Some("1"));
        assert_eq!(info.or_addr, Some("127.0.0.1:9001".parse().unwrap()));
        let env = MapEnv(HashMap::from([("TOR_PT_MANAGED_TRANSPORT_VER", "2")]));
        assert!(server_setup(&env, &tor).is_err());
        assert_eq!(
            lines.lock().unwrap().last().unwrap(),
            "VERSION-ERROR no-version"
        );
    }

    #[test]
    fn launch_mode() {
        let (tor, lines) = TorControl::capture();
        let env = |pairs: &[(&'static str, &'static str)]| MapEnv(pairs.iter().copied().collect());
        assert_eq!(
            is_client(&env(&[("TOR_PT_CLIENT_TRANSPORTS", "obfs4")]), &tor),
            Ok(true)
        );
        assert_eq!(
            is_client(&env(&[("TOR_PT_SERVER_TRANSPORTS", "obfs4")]), &tor),
            Ok(false)
        );
        assert!(is_client(&env(&[]), &tor).is_err());
        assert!(lines.lock().unwrap().is_empty());
        let both = env(&[
            ("TOR_PT_CLIENT_TRANSPORTS", "obfs4"),
            ("TOR_PT_SERVER_TRANSPORTS", "obfs4"),
        ]);
        assert!(is_client(&both, &tor).is_err());
        assert_eq!(
            *lines.lock().unwrap(),
            ["ENV-ERROR TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set"]
        );
    }
}
