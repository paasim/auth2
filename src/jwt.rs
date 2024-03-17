use crate::base64::{base64url_decode, base64url_encode};
use crate::err::Res;
use crate::es256::{Es256, Verify};
use openssl::rand::rand_bytes;
use openssl::sha::sha256;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn base64url_trimmed_encode(plain: impl AsRef<[u8]>) -> String {
    base64url_encode(plain).trim_end_matches('=').to_string()
}

fn base64url_decode_json<T: DeserializeOwned>(encoded: &str) -> Res<T> {
    base64url_decode(encoded).and_then(|v| Ok(serde_json::from_slice(&v)?))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JwtHeader {
    alg: String,
    typ: String,
}

impl JwtHeader {
    pub fn es_256() -> Self {
        Self {
            typ: String::from("JWT"),
            alg: String::from("ES256"),
        }
    }

    fn validate_typ(&self) -> Res<()> {
        if self.typ != "JWT" {
            Err(format!("incorrect typ {} != JWT", self.typ))?
        }
        Ok(())
    }

    fn validate_alg(&self) -> Res<()> {
        if self.alg != "ES256" {
            Err(format!("incorrect alg {} != ES256", self.alg))?
        }
        Ok(())
    }

    fn validate(&self) -> Res<()> {
        self.validate_typ()?;
        self.validate_alg()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JwtPayload {
    iss: String,
    sub: String,
    aud: String,
    exp: u32,
    scope: String,
    challenge: String,
}

impl JwtPayload {
    fn new(aud: String, iss: String, sub: [u8; 8], ttl_minutes: u32, scope: String) -> Res<Self> {
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut challenge = [0; 16];
        rand_bytes(&mut challenge)?;
        Ok(Self {
            aud,
            iss,
            sub: base64url_encode(sub),
            exp: time.as_secs() as u32 + ttl_minutes * 60,
            scope,
            challenge: base64url_encode(challenge),
        })
    }

    fn validate_issuer_hash(&self, iss_hash: &[u8]) -> Res<()> {
        let hash = sha256(self.iss.as_bytes());
        if hash != iss_hash {
            let e = format!("issuer hashes differ: {:?} != {:?}", hash, iss_hash);
            Err(e)?;
        }
        Ok(())
    }

    fn validate_audience(&self, audience: &str) -> Res<()> {
        if self.aud != audience {
            Err(format!("audiences differ: {} != {}", self.aud, audience))?;
        };
        Ok(())
    }

    fn validate_exp(&self) -> Res<()> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        if ts > self.exp {
            Err(format!("expired jwt: {} > {}", ts, self.exp))?;
        }
        Ok(())
    }

    fn validate_scope(&self, scope: &str) -> Res<()> {
        if self.scope != scope {
            Err(format!("scopes differ: {} != {}", self.scope, scope))?;
        };
        Ok(())
    }

    fn validate_challenge(&self, challenge: &[u8]) -> Res<()> {
        let self_challenge = base64url_decode(&self.challenge)?;
        if self_challenge != challenge {
            let e = format!("challenges differ: {:?} != {:?}", self_challenge, challenge);
            Err(e)?;
        };
        Ok(())
    }

    fn get_user_id(&self) -> Res<[u8; 8]> {
        let v = base64url_decode(&self.sub)?;
        Ok(<[u8; 8]>::try_from(v.as_ref())?)
    }
}

#[derive(Debug)]
pub struct Jwt {
    header: JwtHeader,
    payload: JwtPayload,
}

impl Jwt {
    pub fn new(
        aud: String,
        iss: String,
        sub: [u8; 8],
        ttl_minutes: u32,
        scope: String,
    ) -> Res<Self> {
        let header = JwtHeader::es_256();
        let payload = JwtPayload::new(aud, iss, sub, ttl_minutes, scope)?;
        Ok(Self { header, payload })
    }

    pub fn parse(jwt: impl AsRef<str>, key: &impl Verify) -> Res<Self> {
        let jwt_components: Vec<&str> = jwt.as_ref().split('.').collect();
        if jwt_components.len() != 3 {
            Err("invalid jwt")?
        }

        let sig = base64url_decode(jwt_components[2])?;
        let data = jwt_components[..2].join(".");
        if !key.verify_sig_rs(data.as_bytes(), &sig)? {
            Err("invalid jwt signature")?
        }

        Ok(Self {
            header: base64url_decode_json(jwt_components[0])?,
            payload: base64url_decode_json(jwt_components[1])?,
        })
    }

    pub fn to_signed(&self, key: &Es256) -> Res<String> {
        let header = serde_json::to_string(&self.header)?;
        let payload = serde_json::to_string(&self.payload)?;
        let data = [header, payload]
            .map(|s| base64url_trimmed_encode(s.as_bytes()))
            .join(".");
        let sig = key.sign_rs(data.as_bytes())?;
        Ok([data, base64url_trimmed_encode(sig)].join("."))
    }

    pub fn validate_basic(&self, scope: &str) -> Res<()> {
        self.header.validate()?;
        self.payload.validate_scope(scope)?;
        self.payload.validate_exp()
    }

    pub fn validate_issuer_hash(&self, iss_hash: &[u8]) -> Res<()> {
        self.payload.validate_issuer_hash(iss_hash)
    }

    pub fn validate_audience(&self, audience: &str) -> Res<()> {
        self.payload.validate_audience(audience)
    }

    pub fn validate_challenge(&self, challenge: &[u8]) -> Res<()> {
        self.payload.validate_challenge(challenge)
    }

    pub fn get_challenge(&self) -> &str {
        &self.payload.challenge
    }

    pub fn get_user_id(&self) -> Res<[u8; 8]> {
        self.payload.get_user_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es256::Es256Pub;

    #[test]
    fn jwt_to_signed_works() {
        let key = Es256::gen().unwrap();
        let pub_key = Es256Pub::try_from(&key).unwrap();
        let aud = String::from("http://audience.com");
        let iss = String::from("http://issuer.com");
        let scope = String::from("rw");
        let header = JwtHeader::es_256();
        let payload = JwtPayload::new(aud, iss, [0; 8], 1, scope).unwrap();
        let jwt = Jwt {
            header: header.clone(),
            payload: payload.clone(),
        }
        .to_signed(&key)
        .unwrap();

        let jwt_components: Vec<&str> = jwt.split('.').collect();
        assert_eq!(jwt_components.len(), 3);
        let sig = base64url_decode(jwt_components[2]).unwrap();
        let data = jwt_components[..2].join(".");
        assert!(key.verify_sig_rs(data.as_bytes(), &sig).unwrap());

        let jwt_parsed = Jwt::parse(&jwt, &pub_key).unwrap();
        assert_eq!(jwt_parsed.header, header);
        assert_eq!(jwt_parsed.payload, payload);
    }

    #[test]
    fn jwt_validation_works() {
        let aud = "http://audience.com";
        let iss = "http://issuer.com";
        let iss_hash = sha256(iss.as_bytes());
        let scope = String::from("rw");
        let header = JwtHeader::es_256();
        let payload = JwtPayload::new(aud.to_string(), iss.to_string(), [0; 8], 1, scope).unwrap();
        let challenge = base64url_decode(&payload.challenge).unwrap();
        let jwt = Jwt { header, payload };

        assert!(jwt.validate_basic("rw").is_ok());
        assert!(jwt.validate_basic("ro").is_err());

        assert!(jwt.validate_issuer_hash(&iss_hash).is_ok());
        assert!(jwt.validate_issuer_hash(&[]).is_err());

        assert!(jwt.validate_audience(aud).is_ok());
        assert!(jwt.validate_audience("").is_err());

        assert!(jwt.validate_challenge(&challenge).is_ok());
        assert!(jwt.validate_challenge(&[]).is_err());
    }
}
