use crate::err::AuthError;
use axum::response;

pub struct HtmlTemplate<T>(pub T);

impl<T: askama::Template> response::IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> response::Response {
        match self.0.render() {
            Ok(s) => response::Html(s).into_response(),
            Err(e) => AuthError::from(e).into_response(),
        }
    }
}
