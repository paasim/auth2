use crate::cert_info::CertInfo;
use crate::conf::Conf;
use crate::db::get_con_pool;
use crate::err::{AuthError, Res};
use crate::es256::Es256;
use crate::html_template::HtmlTemplate;
use crate::jwt::default_jwt;
use crate::x509::X509Cert;
use askama::Template;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::{http::header, response, routing};
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{Level, Span};
use url::Url;

#[tokio::main]
pub async fn run(conf: Conf) -> Res<()> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .init();
    let trace = TraceLayer::new_for_http()
        .make_span_with(default_span)
        .on_response(log_status);

    let key1 = Arc::new((conf.jwt_key, conf.issuer, conf.audience, conf.ttl));
    let ca = Arc::new(conf.ca_cert);
    let pool = get_con_pool(&conf.db_url).await?;
    let app = Router::new()
        .route("/", routing::get(response::Redirect::to("/certs")))
        .route("/jwt", routing::get(jwt_endpoint))
        .with_state(key1)
        .route("/cert", routing::post(crt_endpoint))
        .route("/certs", routing::get(certs_endpoint))
        .with_state((ca, conf.cert_days, pool))
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

#[derive(Debug, Deserialize)]
struct NewCert {
    name: String,
    password: String,
}

#[derive(Template)]
#[template(path = "certs.html")]
struct Certs {
    certs: Vec<CertInfo>,
}

mod filters {
    pub fn format_fpr(v: &[u8]) -> ::askama::Result<String> {
        let hex = v.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>();
        Ok(hex[..16].join(":") + "\n" + &hex[16..32].join(":"))
    }
    pub fn format_date(d: &time::OffsetDateTime) -> ::askama::Result<String> {
        Ok(d.date().to_string())
    }
}

impl NewCert {
    fn validate_name(&self) -> Res<()> {
        if self.name.len() < 4 {
            return Err(AuthError::from("name too short"));
        }
        if self
            .name
            .chars()
            .any(|f| !(f.is_alphanumeric() || f == '.' || f == '-'))
        {
            return Err(AuthError::from("non-alphanumeric (including .-) name"));
        }
        Ok(())
    }
    fn validate_password(&self) -> Res<()> {
        if self.password.len() < 8 {
            return Err(AuthError::from("password too short"));
        }
        Ok(())
    }
    fn validate(&self) -> Res<()> {
        self.validate_name()?;
        self.validate_password()
    }
}

async fn certs_endpoint<S, T>(
    State((_, _, pool)): State<(S, T, SqlitePool)>,
) -> Res<HtmlTemplate<Certs>> {
    let certs = CertInfo::get_all(&pool).await?;
    Ok(HtmlTemplate(Certs { certs }))
}

async fn crt_endpoint(
    State((ca, cert_days, pool)): State<(Arc<X509Cert>, u32, SqlitePool)>,
    Form(new_cert): Form<NewCert>,
) -> Res<Response> {
    new_cert.validate()?;
    let ca = ca.as_ref();
    let client = X509Cert::new_client(ca, &new_cert.name, cert_days)?;
    CertInfo::try_from(&client)?.insert_cert(&pool).await?;
    let data = client.to_pkcs12_der(&new_cert.name, &new_cert.password)?;
    let headers = [
        (
            header::CONTENT_TYPE,
            "application/pkcs8-encrypted".to_string(),
        ),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}.p12\"", new_cert.name),
        ),
    ];
    Ok((headers, data).into_response())
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
