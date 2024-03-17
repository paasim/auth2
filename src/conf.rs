use crate::err::Res;
use crate::es256::Es256;
use crate::x509::X509Cert;
use std::{env, fs};

pub struct Conf {
    pub jwt_key: Es256,
    pub ca_cert: X509Cert,
    pub issuer: String,
    pub audience: String,
    pub ttl: u32,
    pub port: u16,
    pub db_url: String,
    pub cert_days: u32,
}

pub fn get_var(var_name: &str) -> Res<String> {
    env::var(var_name).map_err(|_| format!("environment variable '{}' missing", var_name).into())
}

impl Conf {
    pub fn read_from_env() -> Res<Self> {
        let ca_pem = fs::read(get_var("CA_PATH")?)?;
        Ok(Conf {
            issuer: get_var("ISSUER")?,
            audience: get_var("AUDIENCE")?,
            ttl: get_var("TTL_MINUTES")?.parse()?,
            port: get_var("PORT")?.parse()?,
            db_url: get_var("DATABASE_URL")?,
            cert_days: get_var("CERT_DAYS")?.parse()?,
            jwt_key: Es256::from_pem(fs::read(get_var("PEM_PATH")?)?)?,
            ca_cert: X509Cert::key_and_crt_from_pem(&ca_pem, &ca_pem)?,
        })
    }
}
