//! Who may call Filament's local HTTP service.
//!
//! The service listens on loopback, has no login, and can hold a signing key. Loopback is not a
//! boundary against the web: any page the user opens can send requests to `127.0.0.1`. So every
//! request is checked here, before any route runs:
//!
//! * **`Host`** must name a loopback address. This stops DNS rebinding, where a page's own domain
//!   is re-pointed at `127.0.0.1` and its requests then look same-origin to the browser.
//! * **`Origin`** (browsers send it on every cross-origin request and on every POST) must be one of:
//!   - a page served from loopback (`http://localhost:…`, `http://127.0.0.1:…`, `http://[::1]:…`),
//!     such as the Filament wallet UI: every route;
//!   - a configured full-access origin (`FILAMENT_ALLOWED_ORIGINS`), for example a browser
//!     extension: every route;
//!   - a testnet portal origin (`FILAMENT_PORTAL_ORIGINS`): only reading the wallet address and
//!     signing a portal sign-in challenge.
//!
//!   Anything else, including `null` (a `file://` page or a sandboxed frame), is refused.
//! * A request **without** `Origin` comes from a program on this machine (`curl`, a script) or is a
//!   browser load whose answer the page cannot read; it passes.
//!
//! Refusing the request matters: leaving out CORS headers only hides the answer, while a "simple"
//! cross-origin POST would still run.
//!
//! This does **not** protect against other programs running on the same machine.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, request::Parts, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use log::{info, warn};
use serde_json::json;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

/// The hosted testnet portal, allowed to sign in with this wallet unless configured otherwise.
pub const DEFAULT_PORTAL_ORIGIN: &str = "https://hcrn-portal.netlify.app";

/// The only requests a portal origin may make.
const PORTAL_ROUTES: [(Method, &str); 2] = [
    (Method::GET, "/wallet/address"),
    (Method::POST, "/wallet/sign-message"),
];

/// Which web origins may call the local service, beyond pages served from loopback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAccessPolicy {
    portal_origins: Vec<String>,
    full_origins: Vec<String>,
}

impl Default for LocalAccessPolicy {
    fn default() -> Self {
        Self::new(vec![DEFAULT_PORTAL_ORIGIN.to_string()], Vec::new())
    }
}

impl LocalAccessPolicy {
    pub fn new(portal_origins: Vec<String>, full_origins: Vec<String>) -> Self {
        let clean = |list: Vec<String>| {
            list.iter()
                .map(|o| o.trim().trim_end_matches('/').to_ascii_lowercase())
                // `null` and `*` are not origins anyone can be trusted by.
                .filter(|o| !o.is_empty() && o != "null" && o != "*")
                .collect()
        };
        Self {
            portal_origins: clean(portal_origins),
            full_origins: clean(full_origins),
        }
    }

    /// `FILAMENT_PORTAL_ORIGINS` (comma-separated; unset means [`DEFAULT_PORTAL_ORIGIN`], empty
    /// means none) and `FILAMENT_ALLOWED_ORIGINS` (comma-separated; unset means none).
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var("FILAMENT_PORTAL_ORIGINS").ok(),
            std::env::var("FILAMENT_ALLOWED_ORIGINS").ok(),
        )
    }

    fn from_values(portal: Option<String>, full: Option<String>) -> Self {
        let split = |v: String| v.split(',').map(str::to_string).collect::<Vec<_>>();
        Self::new(
            portal
                .map(split)
                .unwrap_or_else(|| vec![DEFAULT_PORTAL_ORIGIN.to_string()]),
            full.map(split).unwrap_or_default(),
        )
    }

    /// May a page at `origin` make this request?
    pub fn origin_allowed(&self, origin: &str, method: &Method, path: &str) -> bool {
        let origin = origin.to_ascii_lowercase();
        if is_loopback_origin(&origin) || self.full_origins.contains(&origin) {
            return true;
        }
        self.portal_origins.contains(&origin)
            && PORTAL_ROUTES.iter().any(|(m, p)| m == method && *p == path)
    }

    /// [`Self::origin_allowed`] for a request; a preflight is judged by the method it asks for.
    fn allows(
        &self,
        origin: &HeaderValue,
        method: &Method,
        headers: &header::HeaderMap,
        path: &str,
    ) -> bool {
        let Ok(origin) = origin.to_str() else {
            return false;
        };
        let method = if method == Method::OPTIONS {
            headers
                .get(header::ACCESS_CONTROL_REQUEST_METHOD)
                .and_then(|v| Method::from_bytes(v.as_bytes()).ok())
                .unwrap_or(Method::OPTIONS)
        } else {
            method.clone()
        };
        self.origin_allowed(origin, &method, path)
    }
}

/// `host` or `host:port` naming this machine's loopback interface.
fn is_loopback_authority(authority: &str) -> bool {
    let (host, port) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(end) => (&authority[..=end], &authority[end + 1..]),
            None => return false,
        }
    } else {
        match authority.find(':') {
            Some(colon) => (&authority[..colon], &authority[colon..]),
            None => (authority, ""),
        }
    };
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    port_ok && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "[::1]")
}

fn is_loopback_origin(origin: &str) -> bool {
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .is_some_and(is_loopback_authority)
}

fn refuse(error: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": error }))).into_response()
}

async fn guard(State(policy): State<Arc<LocalAccessPolicy>>, req: Request, next: Next) -> Response {
    let host_ok = match req.headers().get(header::HOST) {
        Some(h) => h.to_str().is_ok_and(is_loopback_authority),
        None => req
            .uri()
            .authority()
            .is_some_and(|a| is_loopback_authority(a.as_str())),
    };
    if !host_ok {
        warn!(
            "Filament refused a request for a non-loopback host: {:?}",
            req.headers().get(header::HOST)
        );
        return refuse("host not allowed");
    }
    let refused = req
        .headers()
        .get_all(header::ORIGIN)
        .iter()
        .find(|o| !policy.allows(o, req.method(), req.headers(), req.uri().path()));
    if let Some(origin) = refused {
        warn!(
            "Filament refused {} {} from web origin {origin:?}",
            req.method(),
            req.uri().path()
        );
        return refuse("origin not allowed");
    }
    next.run(req).await
}

/// Put the access check and matching CORS headers in front of every route of `router`.
pub fn protect(router: Router, policy: LocalAccessPolicy) -> Router {
    info!(
        "Filament local API: web access for loopback pages and {:?}; portal sign-in only for {:?}",
        policy.full_origins, policy.portal_origins
    );
    let policy = Arc::new(policy);
    let for_cors = policy.clone();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &HeaderValue, parts: &Parts| {
                for_cors.allows(origin, &parts.method, &parts.headers, parts.uri.path())
            },
        ))
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request());
    // The layer added last runs first: refuse before CORS answers a preflight.
    router
        .layer(cors)
        .layer(middleware::from_fn_with_state(policy, guard))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_authorities_pass() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:7380",
            "localhost:5176",
            "LocalHost",
            "[::1]",
            "[::1]:7380",
        ] {
            assert!(is_loopback_authority(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.example",
            "evil.example:7380",
            "localhost.evil.example",
            "127.0.0.1.evil.example",
            "evil.example@127.0.0.1",
            "127.0.0.1:7380.evil.example",
            "127.0.0.1:",
            "127.0.0.1/x",
            "[::1",
            "[::1]evil",
            "0.0.0.0:7380",
            "192.168.1.10:7380",
        ] {
            assert!(!is_loopback_authority(bad), "{bad}");
        }
    }

    #[test]
    fn origins_get_only_what_they_are_allowed() {
        let p = LocalAccessPolicy::default();
        for origin in [
            "http://localhost:5176",
            "http://127.0.0.1:7380",
            "https://[::1]:8443",
        ] {
            assert!(
                p.origin_allowed(origin, &Method::POST, "/wallet/send"),
                "{origin}"
            );
        }
        for origin in [
            "null",
            "https://evil.example",
            "http://localhost.evil.example",
            "file://",
            "chrome-extension://abcdefgh",
            "https://hcrn-portal.netlify.app.evil.example",
            "http://hcrn-portal.netlify.app",
        ] {
            for (method, path) in [
                (Method::POST, "/wallet/send"),
                (Method::GET, "/wallet/address"),
                (Method::POST, "/wallet/sign-message"),
            ] {
                assert!(
                    !p.origin_allowed(origin, &method, path),
                    "{origin} {method} {path}"
                );
            }
        }
        let portal = DEFAULT_PORTAL_ORIGIN;
        assert!(p.origin_allowed(portal, &Method::GET, "/wallet/address"));
        assert!(p.origin_allowed(portal, &Method::POST, "/wallet/sign-message"));
        for (method, path) in [
            (Method::POST, "/wallet/send"),
            (Method::POST, "/wallet/sign"),
            (Method::GET, "/wallet/balance"),
            (Method::POST, "/wallet/address"),
            (Method::GET, "/wallet/sign-message"),
            (Method::GET, "/wallet/address/"),
            (Method::POST, "/config"),
            (Method::GET, "/accounts"),
        ] {
            assert!(
                !p.origin_allowed(portal, &method, path),
                "portal {method} {path}"
            );
        }
    }

    #[test]
    fn environment_values_replace_the_defaults() {
        assert_eq!(
            LocalAccessPolicy::from_values(None, None),
            LocalAccessPolicy::default()
        );
        let none = LocalAccessPolicy::from_values(Some(String::new()), None);
        assert!(!none.origin_allowed(DEFAULT_PORTAL_ORIGIN, &Method::GET, "/wallet/address"));
        let set = LocalAccessPolicy::from_values(
            Some("https://portal.example/".into()),
            Some(" chrome-extension://abc , null, * ".into()),
        );
        assert!(set.origin_allowed("https://portal.example", &Method::GET, "/wallet/address"));
        assert!(!set.origin_allowed("https://portal.example", &Method::POST, "/wallet/send"));
        assert!(set.origin_allowed("chrome-extension://abc", &Method::POST, "/wallet/send"));
        assert!(!set.origin_allowed("null", &Method::POST, "/wallet/send"));
        assert!(!set.origin_allowed("https://evil.example", &Method::POST, "/wallet/send"));
    }
}
