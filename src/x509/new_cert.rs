use super::{CertInfo, X509Cert};
use crate::err::{AuthError, Res};
use crate::html_template::HtmlTemplate;
use askama::Template;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct NewCert {
    name: String,
    password: String,
}

#[derive(Template)]
#[template(path = "certs.html")]
pub struct Certs {
    certs: Vec<CertInfo>,
}

impl NewCert {
    fn validate_name(&self) -> Res<()> {
        if self.name.len() < 4 {
            Err("name too short")?
        }
        let valid_chars = |f: char| f.is_alphanumeric() || f == '.' || f == '-';
        if !self.name.chars().all(valid_chars) {
            Err("non-alphanumeric (including .-) name")?
        }
        Ok(())
    }
    fn validate_password(&self) -> Res<()> {
        if self.password.len() < 8 {
            Err("password too short")?
        }
        Ok(())
    }
    fn validate(&self) -> Res<()> {
        self.validate_name()
            .and_then(|_| self.validate_password())
            .map_err(|e| AuthError::InvalidNewCert(e.to_string()))
    }
}

pub async fn certs_endpoint<S, T>(
    State((_, _, pool)): State<(S, T, SqlitePool)>,
) -> Res<HtmlTemplate<Certs>> {
    let certs = CertInfo::get_all(&pool).await?;
    Ok(HtmlTemplate(Certs { certs }))
}

pub async fn crt_endpoint(
    State((ca, cert_days, pool)): State<(Arc<X509Cert>, u32, SqlitePool)>,
    Form(new_cert): Form<NewCert>,
) -> Res<Response> {
    new_cert.validate()?;
    let ca = ca.as_ref();
    let client = X509Cert::new_client(ca, &new_cert.name, cert_days)?;
    CertInfo::try_from(&client)?.insert_cert(&pool).await?;
    let data = client.to_pkcs12_der(&new_cert.name, &new_cert.password)?;
    let ct = "application/pkcs8-encrypted".to_string();
    let cd = format!("attachment; filename=\"{}.p12\"", new_cert.name);
    let headers = [
        (header::CONTENT_TYPE, ct),
        (header::CONTENT_DISPOSITION, cd),
    ];
    Ok((headers, data).into_response())
}
