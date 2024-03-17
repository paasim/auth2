use super::public_key_credential::PublicKeyCredential;
use super::user::User;
use super::RpInfo;
use crate::err::{AuthError, Res};
use crate::es256::{Es256, Verify};
use crate::html_template::HtmlTemplate;
use crate::jwt::Jwt;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Clone, Deserialize, Serialize)]
pub struct AuthData {
    ids: Vec<String>,
    session_token: String,
}

#[allow(dead_code)] // for testing
impl AuthData {
    pub fn ids(&self) -> &[String] {
        &self.ids
    }
    pub fn session_token(&self) -> &str {
        &self.session_token
    }
}

pub async fn auth_data_endpoint(
    State((rp_info, key, pool)): State<(RpInfo, Arc<Es256>, SqlitePool)>,
    usr: Query<User>,
) -> Res<Json<AuthData>> {
    let sub = usr.get_id(&pool).await?;
    let token = Jwt::new(rp_info.name, rp_info.id, sub, 10, String::from("webauthn"))?;
    Ok(Json(AuthData {
        ids: usr.get_pk(&pool).await?,
        session_token: token.to_signed(&key)?,
    }))
}

#[derive(Deserialize, Template)]
#[template(path = "authenticate.html")]
pub struct AuthenticationForm {
    name: Option<String>,
}

pub async fn auth_form(Query(form): Query<AuthenticationForm>) -> HtmlTemplate<AuthenticationForm> {
    HtmlTemplate(form)
}

pub async fn authenticate(
    State((rp_info, key, pool)): State<(RpInfo, Arc<Es256>, SqlitePool)>,
    Form(pkc): Form<PublicKeyCredential>,
) -> Res<Response> {
    let (user_cred, signed_data, sig) = pkc.extract_auth_data(key.as_ref())?;
    let cred_pk = user_cred.get_pk(&pool).await?;
    if !cred_pk.verify_sig_der(&signed_data, &sig)? {
        Err(AuthError::AuthError("invalid signature".to_string()))?
    }

    let ttl_min = 60;
    let jwt = Jwt::new(
        rp_info.name,
        rp_info.id,
        user_cred.user_id(),
        ttl_min,
        String::from("cert"),
    )?;
    let ck = format!(
        "Authorization={}; Max-Age={}; Secure; Path=/",
        jwt.to_signed(key.as_ref())?,
        ttl_min * 60
    );
    let headers = [(SET_COOKIE, ck)];
    Ok((headers, Redirect::to("/certs/all")).into_response())
}
