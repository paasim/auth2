use std::{error, fmt, io, string};

#[derive(Debug)]
pub enum AuthError {
    Axum(axum::Error),
    AxumHttp(axum::http::Error),
    OpenSSL(openssl::error::ErrorStack),
    Other(String),
}

pub type Res<T> = Result<T, AuthError>;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Axum(e) => write!(f, "{}", e),
            AuthError::AxumHttp(e) => write!(f, "{}", e),
            AuthError::OpenSSL(e) => write!(f, "{}", e),
            AuthError::Other(e) => write!(f, "{}", e),
        }
    }
}

pub fn opt_to_res<T>(opt: Option<T>, err: &str) -> Res<T> {
    match opt {
        Some(t) => Ok(t),
        None => Err(AuthError::Other(err.to_string())),
    }
}

impl error::Error for AuthError {}

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
