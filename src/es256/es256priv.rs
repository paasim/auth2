use super::es256pub::Es256Pub;
use super::{get_grp, Verify};
use crate::err::{AuthError, Res};
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::Private;
use openssl::sha::sha256;

#[derive(Debug)]
pub struct Es256Priv {
    key: EcKey<Private>,
}

impl Es256Priv {
    pub fn gen() -> Res<Self> {
        let key = EcKey::generate(get_grp()?.as_ref())?;
        Ok(Self { key })
    }

    pub fn from_pem(pem: impl AsRef<[u8]>) -> Res<Self> {
        let key = EcKey::private_key_from_pem(pem.as_ref())?;
        if key.group().curve_name() != get_grp()?.curve_name() {
            Err("Invalid group {}")?
        }
        Ok(Self { key })
    }

    pub fn sign_rs(&self, data: &[u8]) -> Res<Vec<u8>> {
        let sig = EcdsaSig::sign(&sha256(data), &self.key)?;
        Ok([sig.r().to_vec(), sig.s().to_vec()].concat())
    }

    pub fn sign_der(&self, data: &[u8]) -> Res<Vec<u8>> {
        let sig = EcdsaSig::sign(&sha256(data), &self.key)?;
        Ok(sig.to_der()?)
    }

    pub fn private_key_pem(&self) -> Res<Vec<u8>> {
        Ok(self.key.private_key_to_pem()?)
    }

    pub fn public_key_pem(&self) -> Res<Vec<u8>> {
        Ok(self.key.public_key_to_pem()?)
    }
}

impl Verify for Es256Priv {
    fn verify_ecdsa(&self, data: &[u8], sig: &EcdsaSig) -> Res<bool> {
        Ok(sig.verify(&sha256(data), &self.key)?)
    }
}

impl TryFrom<&Es256Priv> for Es256Pub {
    type Error = AuthError;

    fn try_from(value: &Es256Priv) -> Result<Self, Self::Error> {
        let key = EcKey::from_public_key(value.key.group(), value.key.public_key())?;
        Ok(Self::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_verified() {
        let key = Es256Priv::gen().unwrap();
        let data = b"this is some data";

        let mut sig = key.sign_rs(data).unwrap();
        assert!(key.verify_sig_rs(data, &sig).unwrap());

        // pubkey alone verifies this
        let pubkey = Es256Pub::try_from(&key).unwrap();
        assert!(pubkey.verify_sig_rs(data, &sig).unwrap());

        sig[0] ^= 17;
        assert!(!key.verify_sig_rs(data, &sig).unwrap());
    }

    #[test]
    fn pem_serde_works() {
        let key = Es256Priv::gen().unwrap();
        let key2 = key.private_key_pem().and_then(Es256Priv::from_pem).unwrap();
        assert_eq!(key.key.private_key(), key2.key.private_key());
    }
}
