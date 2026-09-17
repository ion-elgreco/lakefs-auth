//! Configuration helpers both servers share: a secret wrapper that never
//! reaches the logs, a comma separated list, and the clap value parser for
//! durations.

use std::fmt;
use std::str::FromStr;

use crate::text::non_blank;

/// A value that never shows up in `Debug` or `Display` output.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl Secret<String> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The value, trimmed, or `None` when it is blank. Every "is this optional
    /// secret set?" question goes through here, so both servers agree that a
    /// whitespace-only token is no token.
    pub fn non_blank(&self) -> Option<&str> {
        non_blank(&self.0)
    }
}

/// A comma separated list on the command line, a `Vec<String>` in the program.
/// Items are trimmed and blank items are dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommaList(pub Vec<String>);

impl CommaList {
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for CommaList {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            value.split(',').filter_map(non_blank).map(str::to_owned).collect(),
        ))
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl FromStr for Secret<String> {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.to_owned()))
    }
}

/// A clap value parser for `30s`, `5m`, `1h`, and the other humantime forms.
#[cfg(feature = "server")]
pub fn parse_duration(value: &str) -> Result<std::time::Duration, String> {
    humantime::parse_duration(value).map_err(|error| format!("invalid duration {value:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_value() {
        let secret = Secret::new("super-secret-value".to_owned());
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert_eq!(secret.expose(), "super-secret-value");
        assert_eq!(secret.as_str(), "super-secret-value");
    }

    #[test]
    fn a_blank_secret_counts_as_absent() {
        assert_eq!(Secret::new("  ".to_owned()).non_blank(), None);
        assert_eq!(Secret::new(" token ".to_owned()).non_blank(), Some("token"));
    }

    #[test]
    fn comma_lists_trim_and_drop_blank_items() {
        let list: CommaList = "a, b ,,c".parse().unwrap();
        assert_eq!(list.as_slice(), ["a", "b", "c"]);
        assert!("".parse::<CommaList>().unwrap().is_empty());
    }

    #[cfg(feature = "server")]
    #[test]
    fn durations_parse_in_the_humantime_forms() {
        assert_eq!(parse_duration("30s"), Ok(std::time::Duration::from_secs(30)));
        assert_eq!(parse_duration("2m"), Ok(std::time::Duration::from_secs(120)));
        assert!(parse_duration("soon").is_err());
    }
}
