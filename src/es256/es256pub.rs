use super::{get_grp, Verify};
use crate::err::Res;
use ciborium::{value, Value};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::Public;
use openssl::sha::sha256;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Es256Pub {
    key: EcKey<Public>,
}

fn from_cbor_int(v: Value) -> Option<isize> {
    v.as_integer().and_then(|i| i.try_into().ok())
}

fn cbor_int<I: Into<value::Integer>>(i: I) -> Value {
    Value::Integer(i.into())
}

impl Es256Pub {
    pub fn new(key: EcKey<Public>) -> Self {
        Self { key }
    }

    pub fn from_xy<B: AsRef<[u8]>>(x: B, y: B) -> Res<Self> {
        let x = BigNum::from_slice(x.as_ref())?;
        let y = BigNum::from_slice(y.as_ref())?;
        let grp = get_grp()?;
        let key = EcKey::<Public>::from_public_key_affine_coordinates(&grp, &x, &y)?;
        Ok(Self { key })
    }

    pub fn to_xy(&self) -> Res<(Vec<u8>, Vec<u8>)> {
        let grp = &get_grp()?;
        let ctx = &mut BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let k = self.key.public_key();
        k.affine_coordinates(grp, &mut x, &mut y, ctx)?;
        Ok((x.to_vec(), y.to_vec()))
    }

    pub fn from_pem(pem: impl AsRef<[u8]>) -> Res<Self> {
        let key = EcKey::public_key_from_pem(pem.as_ref())?;
        if key.group().curve_name() != get_grp()?.curve_name() {
            Err("Invalid group {}")?
        }
        Ok(Self { key })
    }

    pub fn to_pem(&self) -> Res<Vec<u8>> {
        Ok(self.key.public_key_to_pem()?)
    }

    pub fn from_cbor(v: impl AsRef<[u8]>) -> Res<Self> {
        let mut pubkey: HashMap<isize, Value> = ciborium::from_reader(v.as_ref())?;
        if pubkey.remove(&1).and_then(from_cbor_int) != Some(2) {
            Err("invalid keytype")?
        }
        if pubkey.remove(&3).and_then(from_cbor_int) != Some(-7) {
            Err("invalid algorithm")?
        }
        if pubkey.remove(&-1).and_then(from_cbor_int) != Some(1) {
            Err("invalid curve")?
        }
        let x = pubkey.remove(&-2).and_then(|v| v.into_bytes().ok());
        let y = pubkey.remove(&-3).and_then(|v| v.into_bytes().ok());
        if let (Some(x), Some(y)) = (x, y) {
            return Self::from_xy(&x, &y);
        }
        Err("invalid point")?
    }

    pub fn to_cbor(&self) -> Res<Vec<u8>> {
        let (x, y) = self.to_xy()?;
        let mut m = HashMap::<isize, Value>::new();
        m.insert(1, cbor_int(2));
        m.insert(3, cbor_int(-7));
        m.insert(-1, cbor_int(1));
        m.insert(-2, Value::Bytes(x));
        m.insert(-3, Value::Bytes(y));
        let mut res = vec![];
        ciborium::into_writer(&m, &mut res)?;
        Ok(res)
    }

    pub fn from_der(v: impl AsRef<[u8]>) -> Res<Self> {
        let key = EcKey::<Public>::public_key_from_der(v.as_ref())?;
        Ok(Self { key })
    }

    pub fn to_der(&self) -> Res<Vec<u8>> {
        Ok(self.key.public_key_to_der()?)
    }
}

impl Verify for Es256Pub {
    fn verify_ecdsa(&self, data: &[u8], sig: &EcdsaSig) -> Res<bool> {
        Ok(sig.verify(&sha256(data), &self.key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es256::Es256;

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // from rfc8392, A.2.3
    fn cbor_rfc8392_a32() -> &'static str {
        "a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858\
         bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db\
         9529971a36e7b9215820143329cce7868e416927599cf65a34f3ce2ffda55a7e\
         ca69ed8919a394d42f0f2001010202524173796d6d6574726963454344534132\
         35360326"
    }

    #[test]
    fn to_cbor_from_cbor_are_inverses() {
        let k = Es256::gen().and_then(|k| Es256Pub::try_from(&k)).unwrap();
        let v = k.to_cbor().unwrap();
        let k2 = Es256Pub::from_cbor(v).unwrap();
        assert_eq!(k.to_der().unwrap(), k2.to_der().unwrap());
    }

    #[test]
    fn from_cbor_parses_correctly() {
        let pk = Es256Pub::from_cbor(from_hex(cbor_rfc8392_a32()));
        assert!(pk.is_ok())
    }

    #[test]
    fn pem_serde_works() {
        let pk = Es256Pub::from_cbor(from_hex(cbor_rfc8392_a32())).unwrap();
        let pk2 = pk.to_pem().and_then(Es256Pub::from_pem).unwrap();
        assert_eq!(pk.to_der().unwrap(), pk2.to_der().unwrap());
    }
}
