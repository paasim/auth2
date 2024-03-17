use crate::es256::{Es256, Es256Pub};
use authentication::auth_data_endpoint;
use authentication::auth_form;
use axum::{routing, Router};
use registration::reg_form;
use sqlx::SqlitePool;
use std::sync::Arc;

pub use authentication::authenticate;
pub use registration::register;

mod authentication;
mod public_key_credential;
mod registration;
mod user;

#[derive(Clone, Debug)]
pub struct RpInfo {
    id: String,
    name: String,
}

impl RpInfo {
    pub fn new(id: String, name: String) -> Self {
        Self { id, name }
    }
}

pub fn webauthn_router(
    rp_info: RpInfo,
    pool: SqlitePool,
    key: Arc<Es256>,
    pub_key: Arc<Es256Pub>,
) -> Router {
    Router::new()
        .route("/register", routing::post(register))
        .with_state((pub_key, pool.clone()))
        .route("/authenticate", routing::post(authenticate))
        .route("/register", routing::get(reg_form))
        .route("/auth_data", routing::get(auth_data_endpoint))
        .with_state((rp_info, key, pool))
        .route("/authenticate", routing::get(auth_form))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::authentication::AuthData;
    use crate::webauthn::{public_key_credential::PublicKeyCredential, user::UserCredential};
    use crate::{base64::base64url_encode, db::get_con_pool, jwt::Jwt};
    use axum::body::{to_bytes, Body, Bytes};
    use axum::http::{header::CONTENT_TYPE, Request};
    use axum::response::Response;
    use std::{str::from_utf8, sync::Arc};
    use tower::{Service, ServiceExt};

    async fn mk_app(rp_info: RpInfo, pool: SqlitePool, key: Arc<Es256>) -> Router {
        let pub_key = Arc::new(Es256Pub::try_from(key.as_ref()).unwrap());
        webauthn_router(rp_info, pool, key, pub_key)
    }

    async fn send(app: &mut Router, req: Request<String>) -> Response<Body> {
        ServiceExt::<Request<Body>>::ready(app)
            .await
            .unwrap()
            .call(req)
            .await
            .unwrap()
    }

    async fn get_body(r: Response<Body>) -> Bytes {
        to_bytes(r.into_body(), usize::MAX).await.unwrap()
    }

    fn get_token_from_html(resp: &Bytes) -> &str {
        let html = from_utf8(resp).unwrap();
        // base64 of a JWT that starts with alg
        let start = html.find("eyJh").unwrap();
        let end = html[start..].find('"').unwrap();
        &html[start..start + end]
    }

    fn mk_form_req(uri: &str, body: String) -> Request<String> {
        Request::post(uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .unwrap()
    }

    #[tokio::test]
    async fn registration_works() {
        let pool = get_con_pool(":memory:").await.unwrap();
        let server_key = Arc::new(Es256::gen().unwrap());
        let audience = "http://example.eu";
        let issuer = "example.eu";
        let rp_info = RpInfo::new(issuer.to_string(), audience.to_string());
        let authenticator = Es256::gen().unwrap();
        let auth_pk = Es256Pub::try_from(&authenticator).unwrap();

        let app = &mut mk_app(rp_info, pool.clone(), server_key.clone()).await;
        let name = "name1";
        let pk_id = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5];

        // get token
        let req = Request::get("/register").body("".to_string()).unwrap();
        let resp = &get_body(send(app, req).await).await;
        let token = get_token_from_html(resp);
        let jwt = Jwt::parse(token, server_key.as_ref()).unwrap();
        let challenge = jwt.get_challenge();

        let reg = PublicKeyCredential::new_reg(
            name.to_owned(),
            issuer.to_owned(),
            audience.to_owned(),
            challenge.to_owned(),
            token.to_owned(),
            &pk_id,
            &auth_pk,
        );
        let req = mk_form_req("/register", reg.unwrap().to_form());
        send(app, req).await;

        // credentials exist in the db
        let user_cred = UserCredential::new(jwt.get_user_id().unwrap(), pk_id.clone());
        let auth_pk_db = user_cred.get_pk(&pool).await.unwrap();
        assert_eq!(auth_pk.to_der().unwrap(), auth_pk_db.to_der().unwrap());

        // get a new token for auth
        let req = Request::get(format!("/auth_data?name={name}"));
        let resp = &get_body(send(app, req.body("".to_string()).unwrap()).await).await;
        let auth_data: AuthData = serde_json::from_slice(resp).unwrap();
        let token = auth_data.session_token();
        // sent public key credential is returned
        assert!(auth_data.ids().contains(&base64url_encode(&pk_id)));

        let jwt = Jwt::parse(token, server_key.as_ref()).unwrap();
        let challenge = jwt.get_challenge();

        // authenticate
        let reg = PublicKeyCredential::new_auth(
            name.to_owned(),
            issuer.to_owned(),
            audience.to_owned(),
            challenge.to_owned(),
            token.to_owned(),
            &pk_id,
            &authenticator,
        );
        let req = mk_form_req("/authenticate", reg.unwrap().to_form());
        let resp = send(app, req).await;

        // check cookie from response
        let cookie = from_utf8(resp.headers().get("Set-Cookie").unwrap().as_bytes()).unwrap();
        let (n, v) = cookie
            .split(';')
            .filter_map(|x| x.split_once('='))
            .next()
            .unwrap();
        assert_eq!(n, "Authorization");

        let jwt = Jwt::parse(v, server_key.as_ref()).unwrap();
        assert!(jwt.validate_basic("cert").is_ok())
    }
}
