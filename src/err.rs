use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::{array, error, fmt, io, str, string};

#[derive(Debug)]
pub enum AuthError {
    Askama(askama::Error),
    AuthError(String),
    Axum(axum::Error),
    AxumHttp(axum::http::Error),
    DbAlreadyExists(sqlx::Error),
    DbNotFound(sqlx::Error),
    InvalidNewCert(String),
    OpenSSL(openssl::error::ErrorStack),
    Other(String),
}

pub type Res<T> = Result<T, AuthError>;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Askama(e) => write!(f, "{}", e),
            AuthError::AuthError(e) => write!(f, "{}", e),
            AuthError::Axum(e) => write!(f, "{}", e),
            AuthError::AxumHttp(e) => write!(f, "{}", e),
            AuthError::DbAlreadyExists(e) => write!(f, "{}", e),
            AuthError::DbNotFound(e) => write!(f, "{}", e),
            AuthError::InvalidNewCert(e) => write!(f, "{}", e),
            AuthError::OpenSSL(e) => write!(f, "{}", e),
            AuthError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for AuthError {}

impl From<askama::Error> for AuthError {
    fn from(value: askama::Error) -> Self {
        Self::Askama(value)
    }
}

impl From<axum::Error> for AuthError {
    fn from(value: axum::Error) -> Self {
        Self::Axum(value)
    }
}

impl From<axum::http::Error> for AuthError {
    fn from(value: axum::http::Error) -> Self {
        Self::AxumHttp(value)
    }
}

impl<T: fmt::Debug> From<ciborium::de::Error<T>> for AuthError {
    fn from(value: ciborium::de::Error<T>) -> Self {
        Self::Other(value.to_string())
    }
}

impl<T: fmt::Debug> From<ciborium::ser::Error<T>> for AuthError {
    fn from(value: ciborium::ser::Error<T>) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<io::Error> for AuthError {
    fn from(value: io::Error) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<string::FromUtf8Error> for AuthError {
    fn from(value: string::FromUtf8Error) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<openssl::error::ErrorStack> for AuthError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(value)
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

impl From<sqlx::Error> for AuthError {
    fn from(value: sqlx::Error) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for AuthError {
    fn from(value: sqlx::migrate::MigrateError) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<array::TryFromSliceError> for AuthError {
    fn from(value: array::TryFromSliceError) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<std::time::SystemTimeError> for AuthError {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<time::error::Format> for AuthError {
    fn from(value: time::error::Format) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<time::error::Parse> for AuthError {
    fn from(value: time::error::Parse) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<time::error::ComponentRange> for AuthError {
    fn from(value: time::error::ComponentRange) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<str::Utf8Error> for AuthError {
    fn from(value: str::Utf8Error) -> Self {
        Self::Other(value.to_string())
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        tracing::event!(tracing::Level::ERROR, error = %self);
        let sc = match self {
            Self::AuthError(_) => StatusCode::UNAUTHORIZED,
            Self::DbAlreadyExists(_) => StatusCode::CONFLICT,
            Self::DbNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidNewCert(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        sc.into_response()
    }
}
