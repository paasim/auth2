use crate::err::Res;
use crate::es256::Es256;
use crate::jwt::default_jwt;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::get;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{Level, Span};
use url::Url;

#[tokio::main]
pub async fn run((key, iss, aud, ttl, port): (Es256, Url, Url, u32, u16)) -> Res<()> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .init();
    let trace = TraceLayer::new_for_http()
        .make_span_with(default_span)
        .on_response(log_status);

    let key1 = Arc::new((key, iss, aud, ttl));
    let app = axum::Router::new()
        .route("/jwt", get(jwt_endpoint))
        .with_state(key1)
        .layer(trace);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;

    tracing::info!("serving on {}", listener.local_addr()?);
    Ok(axum::serve(listener, app).await?)
}

#[derive(Debug, Deserialize, Serialize)]
struct Token {
    token: String,
}

async fn jwt_endpoint(State(state): State<Arc<(Es256, Url, Url, u32)>>) -> Res<Json<Token>> {
    let (key, iss, aud, ttl_minutes) = state.as_ref();
    let token = default_jwt(aud, iss, *ttl_minutes, key)?;
    Ok(Json(Token { token }))
}

fn default_span(request: &Request) -> Span {
    let request_method = request.method();
    let request_uri = request.uri();
    let request_version = request.version();
    let request_headers = request.headers();
    tracing::info_span!(
        "request",
        "method={} uri={} version={:?} headers={:?}",
        request_method,
        request_uri,
        request_version,
        request_headers
    )
}

fn log_status(response: &Response, latency: Duration, _span: &Span) {
    let stat = response.status();
    if stat.is_client_error() || stat.is_server_error() {
        tracing::error!("{} in {:?}", stat, latency)
    } else {
        tracing::info!("{} in {:?}", stat, latency)
    }
}
