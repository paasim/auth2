use std::{error, fmt, io, time};

#[derive(Debug)]
pub enum AuthError {
    Axum(axum::Error),
    OpenSSL(openssl::error::ErrorStack),
    Other(String),
}

pub type Res<T> = Result<T, AuthError>;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Axum(e) => write!(f, "{}", e),
            AuthError::OpenSSL(e) => write!(f, "{}", e),
            AuthError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for AuthError {}

impl From<axum::Error> for AuthError {
    fn from(value: axum::Error) -> Self {
        Self::Axum(value)
    }
}

impl From<io::Error> for AuthError {
    fn from(value: io::Error) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<openssl::error::ErrorStack> for AuthError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}

impl From<url::ParseError> for AuthError {
    fn from(value: url::ParseError) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<core::num::ParseIntError> for AuthError {
    fn from(value: core::num::ParseIntError) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(value: serde_json::Error) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<String> for AuthError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&str> for AuthError {
    fn from(value: &str) -> Self {
        Self::Other(value.to_owned())
    }
}

impl From<time::SystemTimeError> for AuthError {
    fn from(value: time::SystemTimeError) -> Self {
        Self::Other(value.to_string())
    }
}

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", self);
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong".to_string(),
        )
            .into_response()
    }
}
