# auth2

[![build](https://github.com/paasim/auth2/workflows/build/badge.svg)](https://github.com/paasim/auth2/actions)

A service with two purposes:
- Obtain JWTs with webauthn
- Generate client-side TLS certificates

## install

The [release builds](https://github.com/paasim/auth2/releases) contain a debian package that consists of two binaries:
- `gen`: generate keys required for running the server, see `man auth2-gen`
- `auth2`: server with `webauthn` registration capabilities (`/webauthn/{authenticate,register}`) and TLS certificate signing capabilities (`/certs/{all,new}`), see `man auth2`

The build [links to system `openssl`](https://docs.rs/openssl/latest/openssl/), so version mismatches might occur.

## development

For development purposes run `make dev`, which generates the keys and starts the server in port `3377`.
