#!/bin/bash

docker run -u "$(id -u):$(id -g)" -v "${PWD}:/home/builder/rust-pkg" --rm cross-compiler
docker run -u "$(id -u):$(id -g)" -v "${PWD}:/home/builder/rust-pkg" --rm \
  cross-compiler aarch64-linux-gnu-strip \
  /home/builder/rust-pkg/target/aarch64-unknown-linux-gnu/release/auth2

docker build -t deb-builder deb

docker run --rm -u "$(id -u):$(id -g)" -v "${PWD}:/pkg" deb-builder \
  deb/build.sh target/aarch64-unknown-linux-gnu/release/auth2 0.1.0 arm64
