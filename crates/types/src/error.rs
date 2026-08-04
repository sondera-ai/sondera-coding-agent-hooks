use std::error::Error as StdError;
use thiserror::Error;

pub(crate) type BoxError = Box<dyn StdError + Send + Sync + 'static>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("validation error: {0}")]
    Message(String),
}

impl ValidationError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

impl From<String> for ValidationError {
    fn from(value: String) -> Self {
        Self::message(value)
    }
}

impl From<&str> for ValidationError {
    fn from(value: &str) -> Self {
        Self::message(value)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentStoreError {
    #[error("agent store error: {0}")]
    Message(String),
    #[error("agent store error: {message}: {source}")]
    Source {
        message: String,
        #[source]
        source: BoxError,
    },
}

impl AgentStoreError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Source {
            message: message.into(),
            source: Box::new(source),
        }
    }
}

impl From<String> for AgentStoreError {
    fn from(value: String) -> Self {
        Self::message(value)
    }
}

impl From<&str> for AgentStoreError {
    fn from(value: &str) -> Self {
        Self::message(value)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EntityStoreError {
    #[error("entity store error: {0}")]
    Message(String),
    #[error("entity store error: {message}: {source}")]
    Source {
        message: String,
        #[source]
        source: BoxError,
    },
}

impl EntityStoreError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Source {
            message: message.into(),
            source: Box::new(source),
        }
    }
}

impl From<String> for EntityStoreError {
    fn from(value: String) -> Self {
        Self::message(value)
    }
}

impl From<&str> for EntityStoreError {
    fn from(value: &str) -> Self {
        Self::message(value)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrajectoryStoreError {
    #[error("trajectory store error: {0}")]
    Message(String),
    #[error("trajectory store error: {message}: {source}")]
    Source {
        message: String,
        #[source]
        source: BoxError,
    },
}

impl TrajectoryStoreError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Source {
            message: message.into(),
            source: Box::new(source),
        }
    }
}

impl From<String> for TrajectoryStoreError {
    fn from(value: String) -> Self {
        Self::message(value)
    }
}

impl From<&str> for TrajectoryStoreError {
    fn from(value: &str) -> Self {
        Self::message(value)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("store not found: {0}")]
    NotFound(String),
    #[error("store conflict: {0}")]
    AlreadyExists(String),
    #[error("store invalid argument: {0}")]
    InvalidArgument(String),
    #[error("store failed precondition: {0}")]
    FailedPrecondition(String),
    #[error("store error: {0}")]
    Message(String),
    #[error("store error: {message}: {source}")]
    Source {
        message: String,
        #[source]
        source: BoxError,
    },
}

impl StoreError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::AlreadyExists(message.into())
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::FailedPrecondition(message.into())
    }

    pub fn source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Source {
            message: message.into(),
            source: Box::new(source),
        }
    }
}

impl From<String> for StoreError {
    fn from(value: String) -> Self {
        Self::message(value)
    }
}

impl From<&str> for StoreError {
    fn from(value: &str) -> Self {
        Self::message(value)
    }
}

impl From<ValidationError> for StoreError {
    fn from(value: ValidationError) -> Self {
        Self::invalid_argument(value.to_string())
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HarnessError {
    #[error("harness error: {0}")]
    Message(String),
    #[error("harness error: {message}: {source}")]
    Source {
        message: String,
        #[source]
        source: BoxError,
    },
}

impl HarnessError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Source {
            message: message.into(),
            source: Box::new(source),
        }
    }
}

impl From<String> for HarnessError {
    fn from(value: String) -> Self {
        Self::message(value)
    }
}

impl From<&str> for HarnessError {
    fn from(value: &str) -> Self {
        Self::message(value)
    }
}

/// The single error type for every harness client interaction — transport
/// setup, the RPC itself, and response decoding.
///
/// Consumers classify failure modes by **matching these variants**, never by
/// scanning `Display` output, so every variant that can reach a caller carries
/// the payload that caller needs to act on.
///
/// There are deliberately no authentication or authorization variants: this
/// harness has no authn/authz: the client sends no credentials and the server
/// never issues `Unauthenticated` or `PermissionDenied`. Modelling failures
/// that cannot occur cost real complexity — it was the sole remaining reason
/// hooks had to inspect message text at all.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike its neighbours here. Every
/// variant must be classified into a hook failure mode by
/// `sondera_hooks::error::HookError`'s `From` impl, and that classifier decides
/// whether an action is denied or allowed through. A catch-all arm there would
/// silently bucket a new wire failure as "service unavailable"; without one,
/// adding a variant breaks the build until someone decides how hooks behave.
#[derive(Debug, Error)]
pub enum HarnessClientError {
    /// The endpoint was missing or unparseable — a local misconfiguration, not
    /// a server or connectivity fault.
    #[error("harness endpoint configuration error: {0}")]
    Config(String),
    #[error("harness unavailable: {0}")]
    Unavailable(String),
    #[error("harness deadline exceeded")]
    Timeout,
    #[error("invalid request: {0}")]
    InvalidArgument(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("server error: {0}")]
    Server(String),
}

impl From<tonic::Status> for HarnessClientError {
    fn from(status: tonic::Status) -> Self {
        use tonic::Code;

        match status.code() {
            Code::Unavailable => Self::Unavailable(status.message().to_owned()),
            Code::DeadlineExceeded => Self::Timeout,
            Code::InvalidArgument => Self::InvalidArgument(status.message().to_owned()),
            Code::NotFound => Self::NotFound(status.message().to_owned()),
            Code::AlreadyExists => Self::AlreadyExists(status.message().to_owned()),
            // Includes `Unauthenticated` and `PermissionDenied`. This harness
            // issues neither, so if one arrives it came from something in front
            // of it (a proxy, a mesh) — which makes "the server refused this
            // request, contact your admin" the right thing to tell the user.
            _ => Self::Server(status.message().to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_cause() -> std::io::Error {
        std::io::Error::other("root cause")
    }

    #[test]
    fn store_source_errors_display_source() {
        assert_eq!(
            format!("{}", AgentStoreError::source("database", root_cause())),
            "agent store error: database: root cause"
        );
        assert_eq!(
            format!("{}", EntityStoreError::source("database", root_cause())),
            "entity store error: database: root cause"
        );
        assert_eq!(
            format!("{}", TrajectoryStoreError::source("database", root_cause())),
            "trajectory store error: database: root cause"
        );
        assert_eq!(
            format!("{}", HarnessError::source("runtime", root_cause())),
            "harness error: runtime: root cause"
        );
    }
}
