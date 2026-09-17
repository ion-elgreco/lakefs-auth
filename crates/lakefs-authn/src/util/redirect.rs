//! Open-redirect protection for the `next` parameter of `/oidc/login`.

use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RedirectError {
    #[error("redirect target is empty")]
    Empty,
    #[error("redirect target contains control characters")]
    ControlCharacter,
    #[error("redirect target is protocol relative")]
    ProtocolRelative,
    #[error("redirect target is not a valid URL")]
    NotAUrl,
    #[error("redirect target uses an unsupported scheme")]
    BadScheme,
    #[error("redirect target host is not allowed")]
    HostNotAllowed,
}

/// Accepts a relative path, or an absolute URL whose origin is explicitly allowed.
///
/// An allow list entry is `host`, `host:port`, or `scheme://host[:port]`. It
/// names one authority: a bare `host` matches the default port only, never
/// every port on that host, and an entry with a scheme pins the scheme.
///
/// Rejects protocol-relative targets (`//evil.test`, `/\evil.test`) and anything
/// carrying CR or LF, which some proxies turn into header injection.
pub fn safe_next(next: &str, allowed_hosts: &[String]) -> Result<String, RedirectError> {
    if next.is_empty() {
        return Err(RedirectError::Empty);
    }
    if next.chars().any(|c| c.is_control()) {
        return Err(RedirectError::ControlCharacter);
    }
    if next.starts_with('/') {
        if is_protocol_relative(next) {
            return Err(RedirectError::ProtocolRelative);
        }
        return Ok(next.to_owned());
    }
    let url = Url::parse(next).map_err(|_| RedirectError::NotAUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(RedirectError::BadScheme);
    }
    let host = url.host_str().ok_or(RedirectError::HostNotAllowed)?;
    // `port()` is `None` for the default port of the scheme, so the authority
    // reads the way the entry is written.
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let allowed = allowed_hosts.iter().any(|entry| match entry.split_once("://") {
        Some((scheme, rest)) => {
            scheme.eq_ignore_ascii_case(url.scheme()) && rest.trim_end_matches('/').eq_ignore_ascii_case(&authority)
        }
        None => entry.eq_ignore_ascii_case(&authority),
    });
    if allowed {
        Ok(next.to_owned())
    } else {
        Err(RedirectError::HostNotAllowed)
    }
}

/// Where the browser goes after login: `next` resolved against the post-login URL.
///
/// A relative `next` stays relative when the post-login URL is relative, which is
/// the reverse proxy deployment where lakeFS and this server share one origin. It
/// becomes absolute when the post-login URL is absolute, which is the split
/// deployment where lakeFS lives on another origin, for example another port.
/// An absolute `next` (already host checked by [`safe_next`]) is used as is.
pub fn resolve_next(post_login_url: &str, next: Option<&str>) -> String {
    let Some(next) = next else {
        return post_login_url.to_owned();
    };
    if Url::parse(next).is_ok() {
        return next.to_owned();
    }
    match Url::parse(post_login_url) {
        Ok(base) => base
            .join(next)
            .map(|url| url.to_string())
            .unwrap_or_else(|_| next.to_owned()),
        Err(_) => next.to_owned(),
    }
}

/// True for `//host`, `/\\host`, and the percent encoded spellings that a
/// normalizing proxy can turn back into a second slash or a backslash.
fn is_protocol_relative(next: &str) -> bool {
    const PREFIXES: [&str; 3] = ["//", "/%2f", "/%5c"];
    let lowered = next.to_ascii_lowercase();
    next.starts_with("/\\") || PREFIXES.iter().any(|prefix| lowered.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_resolves_against_the_post_login_url() {
        assert_eq!(resolve_next("/", None), "/");
        assert_eq!(resolve_next("http://lakefs.test/", None), "http://lakefs.test/");
        // Same origin behind a proxy: relative stays relative.
        assert_eq!(resolve_next("/", Some("/repositories")), "/repositories");
        // lakeFS on another origin: relative becomes absolute on that origin.
        assert_eq!(
            resolve_next("http://localhost:8000/", Some("/repositories")),
            "http://localhost:8000/repositories"
        );
        assert_eq!(
            resolve_next("http://localhost:8000/lakefs/", Some("/a/b?c=d#e")),
            "http://localhost:8000/a/b?c=d#e"
        );
        // An absolute next that passed the host check is kept.
        assert_eq!(
            resolve_next("http://localhost:8000/", Some("https://lakefs.example.com/x")),
            "https://lakefs.example.com/x"
        );
    }

    #[test]
    fn relative_paths_pass() {
        for value in ["/", "/repositories", "/a/b?c=d#e", "/a%2Fb"] {
            assert_eq!(safe_next(value, &[]).unwrap(), value, "{value}");
        }
    }

    #[test]
    fn open_redirect_attempts_fail() {
        let cases = [
            ("", RedirectError::Empty),
            ("//evil.test/", RedirectError::ProtocolRelative),
            ("/\\evil.test/", RedirectError::ProtocolRelative),
            ("/%2Fevil.test/", RedirectError::ProtocolRelative),
            ("/%5Cevil.test/", RedirectError::ProtocolRelative),
            ("/%2fevil.test/", RedirectError::ProtocolRelative),
            ("/ok\r\nSet-Cookie: x=1", RedirectError::ControlCharacter),
            ("/ok\nnext", RedirectError::ControlCharacter),
            ("https://evil.test/", RedirectError::HostNotAllowed),
            ("javascript:alert(1)", RedirectError::BadScheme),
            ("relative/path", RedirectError::NotAUrl),
        ];
        for (value, expected) in cases {
            assert_eq!(safe_next(value, &[]).unwrap_err(), expected, "{value}");
        }
    }

    #[test]
    fn absolute_urls_need_an_allowed_host() {
        let allowed = vec!["lakefs.example.com".to_owned(), "localhost:8000".to_owned()];
        assert!(safe_next("https://lakefs.example.com/x", &allowed).is_ok());
        assert!(safe_next("https://LAKEFS.example.com/x", &allowed).is_ok());
        assert!(safe_next("http://localhost:8000/x", &allowed).is_ok());
        assert!(safe_next("http://localhost:9000/x", &allowed).is_err());
        assert!(safe_next("https://other.example.com/x", &allowed).is_err());
    }

    /// A bare entry names one authority, not every port on that host, and an
    /// entry with a scheme pins the scheme too.
    #[test]
    fn an_entry_matches_one_authority_and_may_pin_the_scheme() {
        let bare = vec!["lakefs.example.com".to_owned()];
        assert!(safe_next("https://lakefs.example.com/x", &bare).is_ok());
        assert!(safe_next("http://lakefs.example.com/x", &bare).is_ok());
        assert!(safe_next("https://lakefs.example.com:8443/x", &bare).is_err());
        assert!(safe_next("http://lakefs.example.com:8000/x", &bare).is_err());

        let pinned = vec!["https://lakefs.example.com".to_owned()];
        assert!(safe_next("https://lakefs.example.com/x", &pinned).is_ok());
        assert!(safe_next("http://lakefs.example.com/x", &pinned).is_err());
        assert!(safe_next("https://lakefs.example.com:8443/x", &pinned).is_err());

        let with_port = vec!["https://lakefs.example.com:8443".to_owned()];
        assert!(safe_next("https://lakefs.example.com:8443/x", &with_port).is_ok());
        assert!(safe_next("https://lakefs.example.com/x", &with_port).is_err());
    }
}
