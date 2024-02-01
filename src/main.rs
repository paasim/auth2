fn main() {
    auth2::conf::Conf::read_from_env()
        .and_then(auth2::server::run)
        .unwrap_or_else(|e| {
            eprintln!("{}", e);
            std::process::exit(1)
        });
}
