//! Structured parse of a WebFetch URL for the Cedar request context.
//!
//! Where policies would otherwise glob the raw URL string
//! (`url like "*…*"`), this exposes the parsed **host**, scheme, and port
//! so a policy can match the host directly. Globbing a raw URL is unsafe:
//! Cedar's `like` wildcard `*` matches `/`, `@`, and `:` too, so
//! `https://trusted.example@evil.com/x.example` cannot be distinguished
//! from an internal host by string matching. WHATWG URL parsing isolates
//! the real host (`evil.com` above), making host allow/deny lists sound.
//!
//! Infallible by design: any parse failure (relative/scheme-less URL,
//! malformed input) degrades to `ok: false` with empty fields rather than
//! an error, so building the Cedar context can never abort adjudication.
//! `ok` is the explicit escape-hatch signal — policies should branch on it
//! and treat `ok: false` conservatively.

use url::Url;

/// Structured view of a fetch URL. Field names/types match
/// `UrlParseContext` in `policies/cedar/base.cedarschema`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct UrlParse {
    /// Parsed as an absolute URL with a scheme. When false, the other
    /// fields are empty/zero.
    ok: bool,
    /// Lowercased scheme without "://" (e.g. "https", "http", "ftp").
    scheme: String,
    /// Lowercased host with userinfo, port, path, query, and fragment
    /// stripped. Empty when the URL has no host (`data:`/`mailto:`,
    /// relative). IPv6 hosts keep their brackets (e.g. "[::1]").
    host: String,
    /// Effective port: the explicit port if present, else the known
    /// default for the scheme (https=443, http=80, …), else 0 for an
    /// unknown scheme or unparseable URL.
    port: i64,
    /// True only when the input explicitly spelled port zero. This remains
    /// private parser metadata: Cedar still sees the effective `port` above.
    explicit_zero_port: bool,
}

impl UrlParse {
    /// Cedar context fragment. Field names/types match `UrlParseContext`
    /// in the schema.
    pub(crate) fn to_cedar_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": self.ok,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
        })
    }

    /// True when the input explicitly spelled `:0`.
    ///
    /// Not part of the Cedar fragment — Cedar only ever sees the effective
    /// `port`. This exists so the tests can pin that an explicit `:0` stays
    /// distinguishable from "unknown port", both of which surface as `port: 0`.
    #[cfg(test)]
    pub(crate) fn has_explicit_zero_port(&self) -> bool {
        self.explicit_zero_port
    }
}

/// Parse `url` into a [`UrlParse`]. Infallible: on any parse failure
/// returns `ok: false` with empty fields rather than an error.
pub(crate) fn parse_url(url: &str) -> UrlParse {
    let Ok(parsed) = Url::parse(url) else {
        return UrlParse::default();
    };

    // url::Url already lowercases the scheme, and the host for special
    // schemes (http/https/ws/wss/ftp). Lowercase the host defensively so
    // non-special schemes match consistently — hostnames are
    // case-insensitive, so this never changes meaning.
    let host = parsed
        .host_str()
        .map(|h| h.to_ascii_lowercase())
        .unwrap_or_default();
    let port = parsed.port_or_known_default().map_or(0, i64::from);
    let explicit_zero_port = parsed.port() == Some(0);

    UrlParse {
        ok: true,
        scheme: parsed.scheme().to_string(),
        host,
        port,
        explicit_zero_port,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_url;

    #[test]
    fn internal_host_with_default_port() {
        let r = parse_url("https://service.example");
        assert!(r.ok);
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "service.example");
        assert_eq!(r.port, 443);
    }

    #[test]
    fn host_isolated_from_path_query_fragment() {
        let r = parse_url("https://git.example/owner/repo?ref=main#frag");
        assert!(r.ok);
        assert_eq!(r.host, "git.example");
    }

    #[test]
    fn explicit_port_and_scheme() {
        let r = parse_url("http://service.example:8080/inbox");
        assert!(r.ok);
        assert_eq!(r.scheme, "http");
        assert_eq!(r.host, "service.example");
        assert_eq!(r.port, 8080);
    }

    #[test]
    fn explicit_zero_port_is_distinguished_without_changing_cedar_shape() {
        let r = parse_url("ssh://service.example:0/");
        assert!(r.ok);
        assert_eq!(r.port, 0);
        assert!(r.has_explicit_zero_port());
        assert_eq!(
            r.to_cedar_json(),
            serde_json::json!({
                "ok": true,
                "scheme": "ssh",
                "host": "service.example",
                "port": 0,
            })
        );

        let unknown_default = parse_url("custom://service.example/");
        assert_eq!(unknown_default.port, 0);
        assert!(!unknown_default.has_explicit_zero_port());
    }

    #[test]
    fn userinfo_does_not_spoof_host() {
        // The whole reason for structured parsing: a string-glob allowlist
        // of `*.example` would wrongly accept this; the real host is evil.com.
        let r = parse_url("https://service.example@evil.com/path");
        assert!(r.ok);
        assert_eq!(r.host, "evil.com");
    }

    #[test]
    fn path_injection_does_not_change_host() {
        let r = parse_url("https://google.com/x.example");
        assert!(r.ok);
        assert_eq!(r.host, "google.com");
    }

    #[test]
    fn ip_literal_host() {
        let r = parse_url("https://1.2.3.4/p.example");
        assert!(r.ok);
        assert_eq!(r.host, "1.2.3.4");
    }

    #[test]
    fn ipv6_host_keeps_brackets() {
        let r = parse_url("https://[::1]:8443/");
        assert!(r.ok);
        assert_eq!(r.host, "[::1]");
        assert_eq!(r.port, 8443);
    }

    #[test]
    fn scheme_and_host_are_lowercased() {
        let r = parse_url("HTTPS://Service.EXAMPLE/X");
        assert!(r.ok);
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "service.example");
    }

    #[test]
    fn scheme_less_url_is_not_ok() {
        let r = parse_url("service.example/inbox");
        assert!(!r.ok);
        assert_eq!(r.host, "");
        assert_eq!(r.port, 0);
    }

    #[test]
    fn garbage_is_not_ok() {
        let r = parse_url("not a url at all");
        assert!(!r.ok);
        assert_eq!(r.scheme, "");
        assert_eq!(r.host, "");
    }

    #[test]
    fn hostless_scheme_parses_ok_with_empty_host() {
        // `data:`/`mailto:` parse fine but have no host; a host allowlist
        // rule will correctly not match (empty host).
        let r = parse_url("data:text/plain,hello");
        assert!(r.ok);
        assert_eq!(r.host, "");
    }
}
