ifneq (,$(wildcard ./.env))
	include .env
	export
endif

.PHONY: build clean dev gen-keys example-env test

build:
	cargo build -r

clean:
	rm -rf target

dev:
	cargo run

gen-keys:
	cargo run -- --gen-keys

example-env:
	cp deb/env .env

test:
	cargo test
