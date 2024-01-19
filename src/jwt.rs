use crate::err::Res;
use crate::es256::Es256;
use openssl::base64::encode_block;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

fn base64url_encode<V: AsRef<[u8]>>(plain: V) -> String {
    encode_block(plain.as_ref())
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

impl JwtHeader {
    fn es_256() -> Self {
        Self {
            typ: String::from("JWT"),
            alg: String::from("ES256"),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct JwtPayload {
    aud: Url,
    iss: Url,
    exp: u32,
    scope: String,
}

fn mk_jwt_data(
    aud: Url,
    iss: Url,
    ttl_minutes: u32,
    scope: String,
) -> Res<(JwtHeader, JwtPayload)> {
    let header = JwtHeader::es_256();
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let payload = JwtPayload {
        aud,
        iss,
        exp: time.as_secs() as u32 + ttl_minutes * 60,
        scope,
    };
    Ok((header, payload))
}

fn to_signed_jwt(header: &JwtHeader, payload: &JwtPayload, key: &Es256) -> Res<String> {
    let header = serde_json::to_string(header).map(|s| base64url_encode(s.as_bytes()))?;
    let payload = serde_json::to_string(payload).map(|p| base64url_encode(p.as_bytes()))?;
    let data = [header, payload].join(".");
    let sig = key.sign(data.as_bytes())?;
    Ok([data, base64url_encode(sig)].join("."))
}

fn signed_jwt(aud: Url, iss: Url, ttl_minutes: u32, scope: String, key: &Es256) -> Res<String> {
    let (header, payload) = mk_jwt_data(aud, iss, ttl_minutes, scope)?;
    to_signed_jwt(&header, &payload, key)
}

pub fn default_jwt(aud: &Url, iss: &Url, ttl_minutes: u32, key: &Es256) -> Res<String> {
    signed_jwt(
        aud.clone(),
        iss.clone(),
        ttl_minutes,
        String::from("default"),
        key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::base64::decode_block;
    use serde::de::DeserializeOwned;

    fn base64url_decode<S: AsRef<str>>(encoded: S) -> Res<Vec<u8>> {
        let mut unpadded = encoded.as_ref().replace('-', "+").replace('_', "/");
        while unpadded.len() % 4 != 0 {
            unpadded.push('=')
        }
        Ok(decode_block(&unpadded)?)
    }

    fn from_b64_json<T: DeserializeOwned>(encoded: &str) -> T {
        let decoded = base64url_decode(encoded).unwrap();
        let json_str = std::str::from_utf8(&decoded).unwrap();
        serde_json::from_str(json_str).unwrap()
    }

    #[test]
    fn to_signed_jwt_works() {
        let key = Es256::gen().unwrap();
        let (header, payload) = mk_jwt_data(
            Url::parse("http://audience.com").unwrap(),
            Url::parse("http://issuer.com").unwrap(),
            1,
            String::from("rw"),
        )
        .unwrap();
        let jwt = to_signed_jwt(&header, &payload, &key).unwrap();

        let jwt_components: Vec<&str> = jwt.split('.').collect();
        assert_eq!(jwt_components.len(), 3);

        let header_parsed: JwtHeader = from_b64_json(jwt_components[0]);
        assert_eq!(header, header_parsed);

        let payload_parsed: JwtPayload = from_b64_json(jwt_components[1]);
        assert_eq!(payload, payload_parsed);

        let sig = base64url_decode(jwt_components[2]).unwrap();
        let data = jwt_components[..2].join(".");
        assert!(key.verify(data.as_bytes(), &sig).unwrap())
    }
}
