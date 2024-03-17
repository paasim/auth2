use axum::{routing, Router};
use new_cert::{certs_endpoint, crt_endpoint};
use sqlx::SqlitePool;
use std::sync::Arc;

pub use cert::X509Cert;
pub use info::CertInfo;

mod cert;
mod info;
mod new_cert;

pub fn x509_router() -> Router<(Arc<X509Cert>, u32, SqlitePool)> {
    Router::new()
        .route("/new", routing::post(crt_endpoint))
        .route("/all", routing::get(certs_endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::get_con_pool;
    use axum::body::{to_bytes, Body, Bytes};
    use axum::http::{header::CONTENT_TYPE, Request};
    use std::{str::from_utf8, sync::Arc};
    use tower::{Service, ServiceExt};

    fn cert_request(name: &str, password: &str) -> Request<String> {
        Request::post("/new")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("name={name}&password={password}"))
            .unwrap()
    }

    async fn send(app: &mut Router, req: Request<String>) -> Bytes {
        let resp = ServiceExt::<Request<Body>>::ready(app)
            .await
            .unwrap()
            .call(req)
            .await
            .unwrap();
        to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    }

    #[tokio::test]
    async fn obtaining_certs_works() {
        let ca = Arc::new(X509Cert::new_ca("ca.example.eu", "example.eu", "EU", 1).unwrap());
        let pool = get_con_pool(":memory:").await.unwrap();
        let app = &mut x509_router().with_state((ca.clone(), 1, pool));
        let password = "password1";

        let resp_body = send(app, cert_request("name1", password)).await;
        let cert = X509Cert::from_pkcs12_der(resp_body, password).unwrap();

        // cert is valid
        assert!(cert.is_signed_by(&ca).unwrap_or(false));
    }

    #[tokio::test]
    async fn obtained_certs_are_stored() {
        let ca = Arc::new(X509Cert::new_ca("ca.example.eu", "example.eu", "EU", 1).unwrap());
        let pool = get_con_pool(":memory:").await.unwrap();
        let app = &mut x509_router().with_state((ca, 1, pool.clone()));
        let names = ["name-for-the-cert", "another-name-for-the-cert"];

        // there is no cert with the given name
        let req = Request::get("/all").body("".to_string()).unwrap();
        let resp_body = send(app, req).await;
        let html = from_utf8(&resp_body).unwrap();
        for name in names {
            assert!(!html.contains(name));
        }

        // add certs
        let mut certs_res = vec![];
        for name in names {
            let resp_body = send(app, cert_request(name, "password1")).await;
            let cert = &X509Cert::from_pkcs12_der(resp_body, "password1").unwrap();
            certs_res.push(CertInfo::try_from(cert).unwrap());
        }
        // sort for comparisons
        certs_res.sort_by_key(|ci| ci.fingerprint());

        // certs in the db equal to the responses
        let mut certs_db = CertInfo::get_all(&pool).await.unwrap();
        certs_db.sort_by_key(|ci| ci.fingerprint());
        assert_eq!(certs_res, certs_db);

        // they are also included in the html
        let req = Request::get("/all").body("".to_string()).unwrap();
        let resp = send(app, req).await;
        let html = from_utf8(&resp).unwrap();
        for cert in certs_res {
            assert!(html.contains(cert.cname()));
            assert!(html.contains(&cert.fingerprint()));
            assert!(html.contains(&cert.not_before()));
            assert!(html.contains(&cert.not_after()));
        }
    }
}
