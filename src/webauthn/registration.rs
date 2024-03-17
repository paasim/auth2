use super::public_key_credential::PublicKeyCredential;
use super::user::User;
use super::RpInfo;
use crate::err::Res;
use crate::es256::{Es256, Es256Pub};
use crate::html_template::HtmlTemplate;
use crate::jwt::Jwt;
use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Deserialize, Template)]
#[template(path = "register.html")]
pub struct RegistrationForm {
    session_token: String,
}

pub async fn reg_form(
    State((rp_info, key, pool)): State<(RpInfo, Arc<Es256>, SqlitePool)>,
) -> Res<HtmlTemplate<RegistrationForm>> {
    let user_id = User::new_id(&pool).await?;
    let session_token = Jwt::new(
        rp_info.name,
        rp_info.id,
        user_id,
        10,
        String::from("webauthn"),
    )
    .and_then(|jwt| jwt.to_signed(&key))?;
    Ok(HtmlTemplate(RegistrationForm { session_token }))
}

pub async fn register(
    State((key, pool)): State<(Arc<Es256Pub>, SqlitePool)>,
    Form(pkc): Form<PublicKeyCredential>,
) -> Res<Response> {
    let (user_name, user_cred, cred_pk) = pkc.extract_reg_data(&key)?;
    User::insert(user_cred.user_id(), &user_name, &pool).await?;
    user_cred.insert(&cred_pk, &pool).await?;

    let uri = format!("/webauthn/authenticate?name={}", user_name);
    Ok(Redirect::to(&uri).into_response())
}
