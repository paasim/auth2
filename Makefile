include .env
export

.env:
	sed -E 's/\/(usr\/share|var\/lib)\/auth2\///' deb/env \
		| sed 's/AUDIENCE.*/AUDIENCE=http:\/\/localhost:3377/g' \
		| sed 's/ISSUER.*/ISSUER=localhost/g' > .env
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

auth2.db: certs
	sqlx database create --sqlite-create-db-wal false
	sqlx migrate run
	cargo sqlx prepare --sqlite-create-db-wal false

certs/es-key.pem: certs .env
	cargo run --bin gen -- es256 > $@

certs/server-crt.pem: certs/ca-crt.pem certs .env
	CA_PATH=$< CN=*.example.eu cargo run --bin gen -- x509-client > $@

clean:
	rm -rf target
	rm -rf certs
	rm -f *.p12
	rm -f *.db
	rm .env

dev: .env certs/ca-crt.pem certs/es-key.pem auth2.db
	cargo run

test:
	cargo test
