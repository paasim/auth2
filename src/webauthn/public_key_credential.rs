use super::user::UserCredential;
use crate::base64::{base64url_decode, base64url_encode};
use crate::err::{AuthError, Res};
use crate::es256::{Es256, Es256Pub, Verify};
use crate::jwt::Jwt;
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct PublicKeyCredential {
    name: String,
    raw_id: String,
    typ: String,
    authenticator_response: String,
    client_data_json: String,
    session_token: String,
}

impl PublicKeyCredential {
    pub fn new_reg(
        name: String,
        issuer: String,
        origin: String,
        challenge: String,
        session_token: String,
        pk_id: &[u8],
        pk: &Es256Pub,
    ) -> Res<Self> {
        let cd = ClientData {
            challenge,
            origin,
            typ: String::from("webauthn.create"),
        };
        let mut att_v = vec![];
        let raw_id = base64url_encode(pk_id);
        let iss_hash = sha256(issuer.as_bytes());
        ciborium::into_writer(&AttestationObject::new(&iss_hash, pk_id, pk)?, &mut att_v)?;
        Ok(Self {
            name,
            raw_id,
            typ: String::from("public-key"),
            authenticator_response: base64url_encode(&att_v),
            client_data_json: base64url_encode(serde_json::to_string(&cd)?),
            session_token,
        })
    }

    pub fn new_auth(
        name: String,
        issuer: String,
        origin: String,
        challenge: String,
        session_token: String,
        pk_id: &[u8],
        pk: &Es256,
    ) -> Res<Self> {
        let cd = ClientData {
            challenge,
            origin,
            typ: String::from("webauthn.get"),
        };
        let raw_id = base64url_encode(pk_id);
        let iss_hash = sha256(issuer.as_bytes());
        let cd_json = serde_json::to_string(&cd)?;
        let cd_hash = sha256(cd_json.as_bytes());
        let auth = [iss_hash.as_slice(), &[69], &[0; 4]].concat();
        let sig = pk.sign_der(&[&auth, cd_hash.as_slice()].concat()).unwrap();
        let auth_resp = format!("{}.{}", base64url_encode(auth), base64url_encode(sig));
        Ok(Self {
            name,
            raw_id,
            typ: String::from("public-key"),
            authenticator_response: auth_resp,
            client_data_json: base64url_encode(cd_json),
            session_token,
        })
    }

    pub fn to_form(&self) -> String {
        format!(
            "name={}&raw_id={}&typ=public-key\
            &authenticator_response={}&client_data_json={}&session_token={}",
            self.name,
            self.raw_id,
            self.authenticator_response,
            self.client_data_json,
            self.session_token
        )
    }

    fn check_name(&self) -> Res<()> {
        if self.name.len() < 4 {
            Err("name too short")?
        }
        let valid_chars = |f: char| f.is_alphanumeric() || f == '.' || f == '-';
        if !self.name.chars().all(valid_chars) {
            Err("non-alphanumeric (including .-) name")?
        }
        Ok(())
    }

    fn check_typ(&self) -> Res<()> {
        if self.typ != "public-key" {
            Err(format!("invalid credential typ {}", self.typ))?
        }
        Ok(())
    }

    fn get_cred_id(&self) -> Res<Vec<u8>> {
        base64url_decode(&self.raw_id)
    }

    fn get_client_data(&self, jwt: &Jwt, exp_type: &str) -> Res<Vec<u8>> {
        let cd_bytes = base64url_decode(&self.client_data_json)?;
        let cd: ClientData = serde_json::from_slice(&cd_bytes)?;
        cd.validate(jwt, exp_type)?;
        Ok(cd_bytes)
    }

    fn get_attestation_object(&self) -> Res<AttestationObject> {
        let att = base64url_decode(&self.authenticator_response)?;
        Ok(ciborium::from_reader(att.as_slice())?)
    }

    fn get_auth_data_and_sig(&self) -> Res<(Vec<u8>, Vec<u8>)> {
        if let Some((ar, sig)) = self.authenticator_response.split_once('.') {
            return Ok((base64url_decode(ar)?, base64url_decode(sig)?));
        };
        Err("invalid authenticator response")?
    }

    fn get_jwt(&self, key: &impl Verify) -> Res<Jwt> {
        let jwt = Jwt::parse(&self.session_token, key)?;
        jwt.validate_basic("webauthn")?;
        Ok(jwt)
    }

    fn _extract_reg_data(self, key: &Es256Pub) -> Res<(String, UserCredential, Es256Pub)> {
        self.check_name()?;

        self.check_typ()?;
        let jwt = self.get_jwt(key)?;

        // validates client data, although bytes are not needed
        self.get_client_data(&jwt, "webauthn.create")?;

        let att = self.get_attestation_object()?;
        let (cred_id, pk) = att.validate(&jwt)?;

        let cred_id0 = self.get_cred_id()?;
        if cred_id != cred_id0 {
            Err("invalid credential id")?
        }

        let cred = UserCredential::new(jwt.get_user_id()?, cred_id);
        Ok((self.name, cred, pk))
    }
    pub fn extract_reg_data(self, key: &Es256Pub) -> Res<(String, UserCredential, Es256Pub)> {
        self._extract_reg_data(key)
            .map_err(|e| AuthError::AuthError(e.to_string()))
    }

    fn _extract_auth_data(&self, key: &impl Verify) -> Res<(UserCredential, Vec<u8>, Vec<u8>)> {
        self.check_typ()?;
        let jwt = self.get_jwt(key)?;

        let cd_bytes = self.get_client_data(&jwt, "webauthn.get")?;

        let (mut signed_data, sig) = self.get_auth_data_and_sig()?;
        validate_auth_data(&signed_data, &jwt)?;

        // signature
        signed_data.extend_from_slice(&sha256(&cd_bytes));

        let cred = UserCredential::new(jwt.get_user_id()?, self.get_cred_id()?);
        Ok((cred, signed_data, sig))
    }
    pub fn extract_auth_data(&self, key: &impl Verify) -> Res<(UserCredential, Vec<u8>, Vec<u8>)> {
        self._extract_auth_data(key)
            .map_err(|e| AuthError::AuthError(e.to_string()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationObject {
    #[serde(rename = "authData")]
    auth_data: Vec<u8>,
    fmt: String,
    #[serde(rename = "attStmt")]
    _att_stmt: AttestationStatement,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationStatement {}

impl AttestationObject {
    fn new(iss_hash: &[u8], pk_id: &[u8], pk: &Es256Pub) -> Res<Self> {
        let pk_cbor = pk.to_cbor()?;
        let id_len = (pk_id.len() as u16).to_be_bytes();
        Ok(Self {
            auth_data: [iss_hash, &[69], &[0; 4], &[0; 16], &id_len, pk_id, &pk_cbor].concat(),
            fmt: String::from("none"),
            _att_stmt: AttestationStatement {},
        })
    }

    fn validate(&self, jwt: &Jwt) -> Res<(Vec<u8>, Es256Pub)> {
        if self.fmt != "none" {
            Err(format!("invalid attestation format {}", self.fmt))?
        }
        // check attestation object
        validate_auth_data(&self.auth_data, jwt)?;
        let _guid = &self.auth_data[37..53]; // not used for anything for now
        let cred_len = u16::from_be_bytes([self.auth_data[53], self.auth_data[54]]) as usize;
        let cred_id = self.auth_data[55..55 + cred_len].to_vec();
        let pk = Es256Pub::from_cbor(&self.auth_data[55 + cred_len..])?;
        Ok((cred_id, pk))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ClientData {
    challenge: String,
    origin: String,
    #[serde(rename = "type")]
    typ: String,
}

impl ClientData {
    fn validate(&self, jwt: &Jwt, exp_typ: &str) -> Res<()> {
        if self.typ != exp_typ {
            Err(format!("invalid client data type {}", self.typ))?
        }
        let challenge = base64url_decode(&self.challenge)?;
        jwt.validate_challenge(&challenge)?;
        jwt.validate_audience(&self.origin)
    }
}

fn validate_auth_data(auth_data: &[u8], jwt: &Jwt) -> Res<usize> {
    jwt.validate_issuer_hash(&auth_data[..32])?;
    if auth_data[32] & 69 == 0 {
        Err("expected AT, UV and UP bits to be set")?;
    }
    // check from db for duplication..?
    let sign_count = u32::from_be_bytes(<[u8; 4]>::try_from(&auth_data[33..37])?) as usize;
    Ok(sign_count)
}
