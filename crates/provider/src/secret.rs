//! A string that never prints itself.

use std::fmt;

/// A credential that redacts itself in `Debug` and `Display` output.
///
/// Guardrail configs are embedded in builders and futures that end up in
/// `tracing` fields, panic messages, and error chains. A plain `String` API key
/// in any of those places writes the credential to the log in cleartext, so the
/// secret is only reachable through the explicit [`expose`](Self::expose).
///
/// ```
/// use sondera_provider::Secret;
///
/// let key = Secret::from("sk-live-abcdef");
/// assert_eq!(format!("{key:?}"), "\"[REDACTED]\"");
/// assert_eq!(key.expose(), "sk-live-abcdef");
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Borrow the underlying secret.
    ///
    /// Every call site is a place the credential can escape; keep them at the
    /// provider boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether no secret was configured (the common case for local Ollama).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: Into<String>> From<T> for Secret {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"[REDACTED]\"")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_the_secret() {
        let secret = Secret::from("sk-live-super-secret");
        assert!(!format!("{secret:?}").contains("super-secret"));
    }

    #[test]
    fn display_does_not_print_the_secret() {
        let secret = Secret::from("sk-live-super-secret");
        assert!(!format!("{secret}").contains("super-secret"));
    }

    #[test]
    fn debug_of_a_containing_struct_does_not_print_the_secret() {
        // The realistic leak: a config struct with a derived `Debug` that ends
        // up in a tracing field or panic message.
        #[derive(Debug)]
        struct Config {
            _api_key: Secret,
        }

        let config = Config {
            _api_key: Secret::from("sk-live-super-secret"),
        };
        assert!(!format!("{config:?}").contains("super-secret"));
    }

    #[test]
    fn expose_returns_the_secret() {
        assert_eq!(Secret::from("sk-live-abc").expose(), "sk-live-abc");
    }
}
