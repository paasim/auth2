use crate::err::{AuthError, Res};
use openssl::asn1::{Asn1Integer, Asn1Time, Asn1TimeRef};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{
    X509Builder, X509Extension, X509Name, X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509,
};
use time::macros::format_description;
use time::OffsetDateTime;

fn mk_serial_number() -> Res<Asn1Integer> {
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    Ok(serial.to_asn1_integer()?)
}

fn mk_name(cname: &str, organization: &str, country: &str) -> Res<X509Name> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", country)?;
    x509_name.append_entry_by_text("O", organization)?;
    x509_name.append_entry_by_text("CN", cname)?;
    Ok(x509_name.build())
}

fn mk_request(name: &str, organization: &str, country: &str, key: &PKey<Private>) -> Res<X509Req> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key)?;
    req_builder.set_subject_name(mk_name(name, organization, country)?.as_ref())?;

    req_builder.sign(key, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

fn parse_time(t: &Asn1TimeRef) -> Res<OffsetDateTime> {
    let fmt = format_description!(
        "[month repr:short] [day padding:space] [hour]:[minute]:[second] [year] [offset_hour]"
    );
    let str = t.to_string().strip_suffix("GMT").unwrap().to_string();
    Ok(OffsetDateTime::parse(&(str + "00"), fmt)?)
}

fn mk_crt_builder(key: &PKey<Private>, days: u32) -> Res<X509Builder> {
    let mut crt_builder = X509::builder()?;
    crt_builder.set_version(2)?;
    crt_builder.set_serial_number(mk_serial_number()?.as_ref())?;
    crt_builder.set_pubkey(key)?;
    crt_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    crt_builder.set_not_after(Asn1Time::days_from_now(days)?.as_ref())?;
    Ok(crt_builder)
}

fn mk_subj_id(builder: &X509Builder, issuer: Option<&X509Ref>) -> Res<X509Extension> {
    Ok(SubjectKeyIdentifier::new().build(&builder.x509v3_context(issuer, None))?)
}

fn mk_auth_id(builder: &X509Builder, issuer: Option<&X509Ref>) -> Res<X509Extension> {
    Ok(AuthorityKeyIdentifier::new()
        .keyid(issuer.is_none())
        .build(&builder.x509v3_context(issuer, None))?)
}

pub struct X509Cert {
    key: PKey<Private>,
    crt: X509,
}

impl X509Cert {
    pub fn new_ca(cname: &str, organization: &str, country: &str, days: u32) -> Res<Self> {
        let key = Rsa::generate(2048).and_then(PKey::from_rsa)?;
        let name = mk_name(cname, organization, country)?;
        let mut crt_builder = mk_crt_builder(&key, days)?;
        crt_builder.set_subject_name(&name)?;
        crt_builder.set_issuer_name(&name)?;

        crt_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        crt_builder.append_extension(mk_subj_id(&crt_builder, None)?)?;
        crt_builder.append_extension(mk_auth_id(&crt_builder, None)?)?;
        crt_builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;

        crt_builder.sign(&key, MessageDigest::sha256())?;
        let crt = crt_builder.build();

        Ok(Self { key, crt })
    }

    pub fn new_client(ca: &Self, cname: &str, days: u32) -> Res<Self> {
        let key = Rsa::generate(2048).and_then(PKey::from_rsa)?;
        let req = mk_request(cname, &ca.get_organization()?, &ca.get_country()?, &ca.key)?;
        let mut crt_builder = mk_crt_builder(&key, days)?;
        crt_builder.set_subject_name(req.subject_name())?;
        crt_builder.set_issuer_name(ca.crt.subject_name())?;

        crt_builder.append_extension(BasicConstraints::new().build()?)?;
        crt_builder.append_extension(mk_subj_id(&crt_builder, Some(&ca.crt))?)?;
        crt_builder.append_extension(mk_auth_id(&crt_builder, Some(&ca.crt))?)?;

        crt_builder.sign(&ca.key, MessageDigest::sha256())?;
        let crt = crt_builder.build();

        Ok(Self { key, crt })
    }

    fn get_entry(&self, nid: Nid) -> Res<String> {
        self.crt
            .subject_name()
            .entries_by_nid(nid)
            .next()
            .ok_or(AuthError::from(format!(
                "{} does not exist",
                nid.short_name()?
            )))
            .and_then(|e| Ok(e.data().as_utf8()?.to_string()))
    }

    pub fn get_cname(&self) -> Res<String> {
        self.get_entry(Nid::COMMONNAME)
    }

    pub fn get_fingerprint(&self) -> Res<Vec<u8>> {
        Ok(self.crt.digest(MessageDigest::sha256())?.to_vec())
    }

    pub fn get_country(&self) -> Res<String> {
        self.get_entry(Nid::COUNTRYNAME)
    }

    pub fn get_organization(&self) -> Res<String> {
        self.get_entry(Nid::ORGANIZATIONNAME)
    }

    pub fn get_not_before(&self) -> Res<OffsetDateTime> {
        parse_time(self.crt.not_before())
    }

    pub fn get_not_after(&self) -> Res<OffsetDateTime> {
        parse_time(self.crt.not_after())
    }

    pub fn crt_to_pem(&self) -> Res<Vec<u8>> {
        Ok(self.crt.to_pem()?)
    }

    pub fn key_to_pem(&self) -> Res<Vec<u8>> {
        Ok(self.key.private_key_to_pem_pkcs8()?)
    }

    pub fn to_pkcs12_der(&self, name: &str, password: &str) -> Res<Vec<u8>> {
        let mut b = Pkcs12::builder();
        b.name(name);
        b.pkey(&self.key);
        b.cert(&self.crt);
        Ok(b.build2(password).and_then(|c| c.to_der())?)
    }

    pub fn key_and_crt_from_pem<T: AsRef<[u8]>>(key_pem: T, crt_pem: T) -> Res<Self> {
        let crt = X509::from_pem(crt_pem.as_ref())?;
        let key = PKey::private_key_from_pem(key_pem.as_ref())?;
        Ok(Self { crt, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::x509::X509VerifyResult;

    #[test]
    fn pem_serialization_works() {
        let x509 = X509Cert::new_ca("ca.example.eu", "example.eu", "EU", 1).unwrap();
        let key = x509.key_to_pem().unwrap();
        let crt = x509.crt_to_pem().unwrap();
        let x5092 = X509Cert::key_and_crt_from_pem(key, crt).unwrap();
        assert_eq!(x509.crt, x5092.crt);
        assert_eq!(
            x509.key.rsa().unwrap().private_key_to_der().unwrap(),
            x5092.key.rsa().unwrap().private_key_to_der().unwrap()
        );
    }

    #[test]
    fn new_ca_sets_cn_o_c_before_after() {
        let cn = String::from("ca.example.eu");
        let o = String::from("example");
        let c = String::from("EU");
        let x509 = X509Cert::new_ca(&cn, &o, &c, 1).unwrap();
        assert_eq!(x509.get_cname().unwrap(), cn);
        assert_eq!(x509.get_organization().unwrap(), o);
        assert_eq!(x509.get_country().unwrap(), c);
        assert!(x509.get_not_before().is_ok());
        assert!(x509.get_not_after().is_ok());
    }

    #[test]
    fn pem_deserialization_works_with_key_and_crt_concatenated() {
        let x509 = X509Cert::new_ca("ca.example.eu", "example", "EU", 1).unwrap();
        let pem = [x509.key_to_pem().unwrap(), x509.crt_to_pem().unwrap()].concat();
        let x5092 = X509Cert::key_and_crt_from_pem(&pem, &pem).unwrap();
        assert_eq!(x509.crt, x5092.crt);
        assert_eq!(
            x509.key.rsa().unwrap().private_key_to_der().unwrap(),
            x5092.key.rsa().unwrap().private_key_to_der().unwrap()
        );
    }

    #[test]
    fn ca_issued_client_works() {
        let ca = X509Cert::new_ca("ca.example.eu", "example", "EU", 1).unwrap();
        assert!(ca.crt.issued(&ca.crt) == X509VerifyResult::OK);
        assert!(ca.crt.verify(&ca.key).unwrap());
        let client = X509Cert::new_client(&ca, "client test", 1).unwrap();
        assert!(client.get_not_before().is_ok());
        assert!(client.get_not_after().is_ok());
        assert!(ca.crt.issued(&client.crt) == X509VerifyResult::OK);
        assert!(client.crt.verify(&ca.key).unwrap());
        assert!(client.crt.issued(&client.crt) != X509VerifyResult::OK);
        assert!(!client.crt.verify(&client.key).unwrap());

        let ca2 = X509Cert::new_ca("ca2.example.eu", "example.eu", "EU", 1).unwrap();
        let client2 = X509Cert::new_client(&ca2, "client2 test", 1).unwrap();
        assert!(ca.crt.issued(&client2.crt) != X509VerifyResult::OK);
        assert!(!client2.crt.verify(&ca.key).unwrap());
        assert!(ca2.crt.issued(&client.crt) != X509VerifyResult::OK);
        assert!(!client.crt.verify(&ca2.key).unwrap());
    }
}
