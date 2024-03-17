use crate::conf::Conf;
use crate::db::get_con_pool;
use crate::err::Res;
use crate::es256::Es256Pub;
use crate::webauthn::{webauthn_router, RpInfo};
use crate::x509::x509_router;
use axum::extract::Request;
use axum::response::{Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{Level, Span};

#[tokio::main]
pub async fn run(conf: Conf) -> Res<()> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .init();
    let trace = TraceLayer::new_for_http()
        .make_span_with(default_span)
        .on_response(log_status);

    let pub_key = Arc::new(Es256Pub::try_from(&conf.jwt_key)?);
    let key = Arc::new(conf.jwt_key);

    let ca = Arc::new(conf.ca_cert);
    let pool = get_con_pool(&conf.db_url).await?;
    let rp_info = RpInfo::new(conf.issuer, conf.audience);
    let webauthn_rtr = webauthn_router(rp_info, pool.clone(), key, pub_key);
    let x509_rtr = x509_router();
    let app = Router::new()
        .route("/", get(Redirect::to("/webauthn/authenticate")))
        .nest("/certs", x509_rtr)
        .with_state((ca, conf.cert_days, pool.clone()))
        .nest("/webauthn", webauthn_rtr)
        .fallback_service(ServeDir::new("static"))
        .layer(trace);
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], conf.port))).await?;

    tracing::info!("serving on {}", listener.local_addr()?);
    Ok(axum::serve(listener, app).await?)
}

#[derive(Debug, Deserialize, Serialize)]
struct Token {
    token: String,
}

fn default_span(request: &Request) -> Span {
    tracing::info_span!("request", "{} {}", request.method(), request.uri())
}

fn log_status(response: &Response, latency: Duration, _span: &Span) {
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        tracing::event!(Level::ERROR, %status, ?latency)
    } else {
        tracing::event!(Level::INFO, %status, ?latency)
    }
}
