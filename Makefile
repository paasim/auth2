include .env
export

.env:
	sed -E 's/\/(usr\/share|var\/lib)\/auth2\///' deb/env > .env
	echo "SQLX_OFFLINE=true" >> .env

certs:
	mkdir -p $@

certs/ca.conf: certs
	sed 's/\/usr\/share\/auth2/./' deb/ca.conf > $@

certs/ca-crl.pem: certs/ca.conf certs/ca-crt.pem certs
	mkdir -p certs/db/newcerts
	touch certs/db/index.txt
	openssl ca -config certs/ca.conf -gencrl -out $@

certs/ca-crt.pem: certs .env
	CN=ca.example.eu O=example C=EU cargo run --bin gen -- x509-ca > $@

certs.db: certs
	sqlx database create
	sqlx migrate run
	cargo sqlx prepare --sqlite-create-db-wal false

certs/es-key.pem: certs .env
	cargo run --bin gen -- es256 > $@

certs/server-crt.pem: certs/ca-crt.pem certs .env
	CA_PATH=$< CN=*.example.eu cargo run --bin gen -- x509-client > $@

clean:
	#rm -rf target
	rm -rf certs
	rm -f *.p12
	rm -f *.db
	rm .env

curl-jwt:
	curl -v --cacert certs/ca-crt.pem \
		--resolve auth.example.eu:443:127.0.0.1 \
		https://auth.example.eu:443/jwt

cert.p12:
	curl -v --cacert certs/ca-crt.pem \
		--resolve auth.example.eu:443:127.0.0.1 \
		-d 'name=cert1&password=password1' \
		https://auth.example.eu:443/cert > $@

curl-secret-certless:
	curl -v --cacert certs/ca-crt.pem \
		--resolve secret.example.eu:443:127.0.0.1 \
		https://secret.example.eu:443

curl-secret: cert.p12
	curl -v --cacert certs/ca-crt.pem \
		--cert-type P12 --cert $<:'password1' \
		--resolve secret.example.eu:443:127.0.0.1 \
		https://secret.example.eu:443

curl-other:
	curl -v --cacert certs/ca-crt.pem \
		--resolve other.example.eu:443:127.0.0.1 \
		https://other.example.eu:443

dev: .env certs/ca-crt.pem certs/es-key.pem certs.db
	cargo run

dev-docker: certs/ca-crt.pem certs/es-key.pem certs.db certs/ca-crl.pem certs/server-crt.pem
	cargo build
	docker compose up

test:
	cargo test
