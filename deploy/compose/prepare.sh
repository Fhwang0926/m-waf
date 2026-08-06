#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

env_file=${MWAF_ENV_FILE:-$script_dir/.env}
secrets_dir=${MWAF_SECRETS_DIR:-$script_dir/secrets}

command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose plugin is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required" >&2; exit 1; }

if [ ! -f "$env_file" ]; then
  mkdir -p "$(dirname -- "$env_file")"
  cp "$script_dir/.env.example" "$env_file"
fi

set -a
. "$env_file"
set +a

umask 077
mkdir -p "$secrets_dir"

create_random_secret() {
  target=$1
  bytes=$2
  if [ ! -e "$target" ]; then
    openssl rand -hex "$bytes" > "$target"
  fi
}

create_random_secret "$secrets_dir/mariadb_app_password" 24
create_random_secret "$secrets_dir/mariadb_root_password" 32
create_random_secret "$secrets_dir/mwaf_session_key" 32

if [ ! -e "$secrets_dir/mwaf_policy_signing_key.pem" ] || [ ! -e "$secrets_dir/mwaf_policy_signing_public.pem" ]; then
  [ ! -e "$secrets_dir/mwaf_policy_signing_key.pem" ] && [ ! -e "$secrets_dir/mwaf_policy_signing_public.pem" ] || { echo "Policy signing key pair is incomplete; restore the missing file" >&2; exit 1; }
  openssl genpkey -algorithm ED25519 -out "$secrets_dir/mwaf_policy_signing_key.pem"
  openssl pkey -in "$secrets_dir/mwaf_policy_signing_key.pem" -pubout -out "$secrets_dir/mwaf_policy_signing_public.pem"
fi

if [ ! -e "$secrets_dir/mwaf_ca_key.pem" ] || [ ! -e "$secrets_dir/mwaf_ca_cert.pem" ]; then
  [ ! -e "$secrets_dir/mwaf_ca_key.pem" ] && [ ! -e "$secrets_dir/mwaf_ca_cert.pem" ] || { echo "CA key/cert pair is incomplete; restore the missing file" >&2; exit 1; }
  openssl genpkey -algorithm ED25519 -out "$secrets_dir/mwaf_ca_key.pem"
  openssl req -x509 -new -key "$secrets_dir/mwaf_ca_key.pem" -out "$secrets_dir/mwaf_ca_cert.pem" -days 3650 -subj "/O=M-WAF/CN=M-WAF Agent CA"
fi

if [ ! -e "$secrets_dir/mwaf_tls_key.pem" ] || [ ! -e "$secrets_dir/mwaf_tls_cert.pem" ]; then
  [ ! -e "$secrets_dir/mwaf_tls_key.pem" ] && [ ! -e "$secrets_dir/mwaf_tls_cert.pem" ] || { echo "TLS key/cert pair is incomplete; restore the missing file" >&2; exit 1; }
  tls_config=$(mktemp)
  trap 'rm -f "$tls_config"' EXIT INT TERM
  cat > "$tls_config" <<EOF
[req]
distinguished_name=dn
req_extensions=req_ext
prompt=no
[dn]
O=M-WAF
CN=${MWAF_MANAGER_HOST:-localhost}
[req_ext]
subjectAltName=@alt_names
[alt_names]
DNS.1=${MWAF_MANAGER_HOST:-localhost}
DNS.2=localhost
IP.1=127.0.0.1
EOF
  openssl genpkey -algorithm ED25519 -out "$secrets_dir/mwaf_tls_key.pem"
  openssl req -new -key "$secrets_dir/mwaf_tls_key.pem" -out "$secrets_dir/mwaf_tls.csr" -config "$tls_config"
  openssl x509 -req -in "$secrets_dir/mwaf_tls.csr" -CA "$secrets_dir/mwaf_ca_cert.pem" -CAkey "$secrets_dir/mwaf_ca_key.pem" -CAcreateserial -out "$secrets_dir/mwaf_tls_cert.pem" -days 825 -extfile "$tls_config" -extensions req_ext
  rm -f "$secrets_dir/mwaf_tls.csr" "$secrets_dir/mwaf_ca_cert.srl"
fi

chmod 0600 "$secrets_dir"/*
echo "Prepared M-WAF deployment secrets without overwriting existing files."
echo "Open the Admin UI to create the first system administrator."
