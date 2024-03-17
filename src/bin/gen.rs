use auth2::conf::get_var;
use auth2::err::{AuthError, Res};
use auth2::es256::Es256;
use auth2::x509::X509Cert;
use std::{env, fs, str};

#[derive(Debug)]
pub enum KeyType {
    Es256,
    X509CA,
    X509Client,
}

impl str::FromStr for KeyType {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "es256" => Ok(Self::Es256),
            "x509-ca" => Ok(Self::X509CA),
            "x509-client" => Ok(Self::X509Client),
            s => Err(AuthError::Other(format!("invalid key type {}", s))),
        }
    }
}

fn get_keytype() -> Res<KeyType> {
    let mut args = env::args();
    args.next().ok_or("expected argument")?;
    args.next().ok_or("expected keytype")?.parse()
}

fn gen_keys(keytype: KeyType) -> Res<()> {
    match keytype {
        KeyType::Es256 => {
            let key = Es256::gen()?;
            print!("{}", String::from_utf8(key.private_key_pem()?)?);
            print!("{}", String::from_utf8(key.public_key_pem()?)?);
        }
        KeyType::X509CA => {
            let org = get_var("O")?;
            let country = get_var("C")?;
            let cn = get_var("CN")?;
            let cert_days = get_var("CERT_DAYS")?.parse()?;
            let crt = X509Cert::new_ca(&cn, &org, &country, cert_days)?;
            print!("{}", String::from_utf8(crt.key_to_pem()?)?);
            print!("{}", String::from_utf8(crt.crt_to_pem()?)?);
        }
        KeyType::X509Client => {
            let ca_pem = fs::read(get_var("CA_PATH")?)?;
            let ca = X509Cert::key_and_crt_from_pem(&ca_pem, &ca_pem)?;
            let cn = get_var("CN")?;
            let cert_days = get_var("CERT_DAYS")?.parse()?;
            let crt = X509Cert::new_client(&ca, &cn, cert_days)?;
            print!("{}", String::from_utf8(crt.key_to_pem()?)?);
            print!("{}", String::from_utf8(crt.crt_to_pem()?)?);
        }
    }
    Ok(())
}

pub fn main() {
    get_keytype().and_then(gen_keys).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1)
    });
}
