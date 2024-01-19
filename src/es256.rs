use crate::err::Res;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sha::sha256;

const GRP_NAME: Nid = Nid::X9_62_PRIME256V1;

fn get_grp() -> Res<EcGroup> {
    Ok(EcGroup::from_curve_name(GRP_NAME)?)
}

#[derive(Debug)]
pub struct Es256 {
    key: EcKey<Private>,
}

impl Es256 {
    pub fn gen() -> Res<Self> {
        let key = EcKey::generate(get_grp()?.as_ref())?;
        Ok(Self { key })
    }

    pub fn from_pem<T: AsRef<[u8]>>(pem: T) -> Res<Self> {
        let key = EcKey::private_key_from_pem(pem.as_ref())?;
        if key.group().curve_name() != Some(GRP_NAME) {
            return Err("Invalid group {}".into());
        }
        Ok(Self { key })
    }

    pub fn sign(&self, data: &[u8]) -> Res<Vec<u8>> {
        let sig = EcdsaSig::sign(&sha256(data), &self.key)?;
        Ok([sig.r().to_vec(), sig.s().to_vec()].concat())
    }

    #[allow(dead_code)] // used for jwt tests
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Res<bool> {
        let r = BigNum::from_slice(&sig[..32])?;
        let s = BigNum::from_slice(&sig[32..64])?;
        let sig = EcdsaSig::from_private_components(r, s)?;
        Ok(sig.verify(&sha256(data), &self.key)?)
    }

    pub fn private_key_pem(&self) -> Res<Vec<u8>> {
        Ok(self.key.private_key_to_pem()?)
    }

    pub fn public_key_pem(&self) -> Res<Vec<u8>> {
        Ok(self.key.public_key_to_pem()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_verified() {
        let key = Es256::gen().unwrap();
        let data = b"this is some data";

        let mut sig = key.sign(data).unwrap();
        assert!(key.verify(data, &sig).unwrap());

        sig[0] ^= 17;
        assert!(!key.verify(data, &sig).unwrap());
    }

    #[test]
    fn private_key_to_pem_works() {
        let key = Es256::gen().unwrap();
        let key2 = key.private_key_pem().and_then(Es256::from_pem).unwrap();
        assert_eq!(key.key.private_key(), key2.key.private_key());
    }
}
