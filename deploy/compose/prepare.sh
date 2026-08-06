#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose plugin is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required" >&2; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
fi

set -a
. ./.env
set +a

umask 077
mkdir -p secrets

create_random_secret() {
  target=$1
  bytes=$2
  if [ ! -e "$target" ]; then
    openssl rand -hex "$bytes" > "$target"
  fi
}

create_random_secret secrets/mariadb_app_password 24
create_random_secret secrets/mariadb_root_password 32
create_random_secret secrets/mwaf_admin_password 18
create_random_secret secrets/mwaf_session_key 32

if [ ! -e secrets/mwaf_policy_signing_key.pem ] || [ ! -e secrets/mwaf_policy_signing_public.pem ]; then
  [ ! -e secrets/mwaf_policy_signing_key.pem ] && [ ! -e secrets/mwaf_policy_signing_public.pem ] || { echo "Policy signing key pair is incomplete; restore the missing file" >&2; exit 1; }
  openssl genpkey -algorithm ED25519 -out secrets/mwaf_policy_signing_key.pem
  openssl pkey -in secrets/mwaf_policy_signing_key.pem -pubout -out secrets/mwaf_policy_signing_public.pem
fi

if [ ! -e secrets/mwaf_ca_key.pem ] || [ ! -e secrets/mwaf_ca_cert.pem ]; then
  [ ! -e secrets/mwaf_ca_key.pem ] && [ ! -e secrets/mwaf_ca_cert.pem ] || { echo "CA key/cert pair is incomplete; restore the missing file" >&2; exit 1; }
  openssl genpkey -algorithm ED25519 -out secrets/mwaf_ca_key.pem
  openssl req -x509 -new -key secrets/mwaf_ca_key.pem -out secrets/mwaf_ca_cert.pem -days 3650 -subj "/O=M-WAF/CN=M-WAF Agent CA"
fi

if [ ! -e secrets/mwaf_tls_key.pem ] || [ ! -e secrets/mwaf_tls_cert.pem ]; then
  [ ! -e secrets/mwaf_tls_key.pem ] && [ ! -e secrets/mwaf_tls_cert.pem ] || { echo "TLS key/cert pair is incomplete; restore the missing file" >&2; exit 1; }
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
  openssl genpkey -algorithm ED25519 -out secrets/mwaf_tls_key.pem
  openssl req -new -key secrets/mwaf_tls_key.pem -out secrets/mwaf_tls.csr -config "$tls_config"
  openssl x509 -req -in secrets/mwaf_tls.csr -CA secrets/mwaf_ca_cert.pem -CAkey secrets/mwaf_ca_key.pem -CAcreateserial -out secrets/mwaf_tls_cert.pem -days 825 -extfile "$tls_config" -extensions req_ext
  rm -f secrets/mwaf_tls.csr secrets/mwaf_ca_cert.srl
fi

chmod 0600 secrets/*
echo "Prepared M-WAF deployment secrets without overwriting existing files."
echo "Admin password: $script_dir/secrets/mwaf_admin_password"
