use crate::err::Res;
use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;

pub use es256priv::Es256Priv as Es256;
pub use es256pub::Es256Pub;

mod es256priv;
mod es256pub;

const GRP_NAME: Nid = Nid::X9_62_PRIME256V1;
fn get_grp() -> Res<EcGroup> {
    Ok(EcGroup::from_curve_name(GRP_NAME)?)
}

pub trait Verify {
    fn verify_ecdsa(&self, data: &[u8], sig: &EcdsaSig) -> Res<bool>;

    fn verify_sig_rs(&self, data: &[u8], sig_rs: &[u8]) -> Res<bool> {
        let r = BigNum::from_slice(&sig_rs[..32])?;
        let s = BigNum::from_slice(&sig_rs[32..64])?;
        let sig = EcdsaSig::from_private_components(r, s)?;
        self.verify_ecdsa(data, &sig)
    }
    fn verify_sig_der(&self, data: &[u8], sig_der: &[u8]) -> Res<bool> {
        let sig = EcdsaSig::from_der(sig_der)?;
        self.verify_ecdsa(data, &sig)
    }
}
