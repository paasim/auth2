use err::Res;
use es256::Es256;
use std::{env, fs};
use url::Url;

mod err;
mod es256;
mod jwt;
mod server;

fn get_var(var_name: &str) -> Res<String> {
    env::var(var_name).map_err(|_| format!("environment variable '{}' missing", var_name).into())
}

fn check_gen_keys() -> Res<bool> {
    let res = env::args().any(|arg| arg == "--gen-keys");
    if res {
        let key = Es256::gen()?;
        fs::write("pub.pem", key.public_key_pem()?)?;
        fs::write("priv.pem", key.private_key_pem()?)?;
    }
    Ok(res)
}

fn get_conf() -> Res<(Es256, Url, Url, u32, u16)> {
    let issuer = get_var("ISSUER")?.parse()?;
    let audience = get_var("AUDIENCE")?.parse()?;
    let ttl = get_var("TTL_MINUTES")?.parse()?;
    let port = get_var("PORT")?.parse()?;
    let pem_path = get_var("PEM_PATH")?;
    let key = Es256::from_pem(fs::read(pem_path)?)?;
    Ok((key, issuer, audience, ttl, port))
}

fn main() {
    if check_gen_keys().unwrap() {
        return;
    }
    get_conf().and_then(server::run).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1)
    });
}
