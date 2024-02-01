#!/bin/bash

set -eu

CA_CONF=/etc/auth2/ca.conf

# eval echo to interpolate dir into the variables...
dir="$(awk -F= '/^dir=/ {print $2}' "$CA_CONF")"
new_certs_dir=$(eval echo "$(awk -F= '/^new_certs_dir=/ {print $2}' "$CA_CONF")")
database=$(eval echo "$(awk -F= '/^database=/ {print $2}' "$CA_CONF")")

mkdir -p "$new_certs_dir"
touch "$database"
openssl ca -config "$CA_CONF" -gencrl -out "$(dirname "$CA_PATH")"/ca-crl.pem
