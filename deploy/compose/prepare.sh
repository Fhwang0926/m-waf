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
chmod 0700 "$secrets_dir"

manager_host=${MWAF_MANAGER_HOST:-localhost}
case "$manager_host" in
  \[*\]) manager_host=${manager_host#\[}; manager_host=${manager_host%\]} ;;
esac
case "$manager_host" in
  ""|*[!A-Za-z0-9._:-]*) echo "MWAF_MANAGER_HOST must be a DNS name or IP address" >&2; exit 1 ;;
esac

is_ipv4_address() {
  address=$1
  old_ifs=$IFS
  IFS=.
  set -- $address
  IFS=$old_ifs
  [ "$#" -eq 4 ] || return 1
  for octet do
    case "$octet" in ""|*[!0-9]*) return 1 ;; esac
    [ "$octet" -le 255 ] || return 1
  done
}

is_ip_address() {
  is_ipv4_address "$1" || case "$1" in *:*) return 0 ;; *) return 1 ;; esac
}

case "$manager_host" in
  *:*) case "$manager_host" in *[!A-Fa-f0-9:.]*) echo "MWAF_MANAGER_HOST contains an invalid IPv6 address" >&2; exit 1 ;; esac ;;
  *[!0-9.]*) ;;
  *.*) is_ipv4_address "$manager_host" || { echo "MWAF_MANAGER_HOST contains an invalid IPv4 address" >&2; exit 1; } ;;
esac

certificate_is_p256() {
  certificate=$1
  openssl x509 -in "$certificate" -noout -text | grep -q 'Public Key Algorithm: id-ecPublicKey' &&
    openssl x509 -in "$certificate" -noout -text | grep -q 'ASN1 OID: prime256v1'
}

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
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$secrets_dir/mwaf_ca_key.pem"
  openssl req -x509 -new -sha256 -key "$secrets_dir/mwaf_ca_key.pem" -out "$secrets_dir/mwaf_ca_cert.pem" -days 3650 -subj "/O=M-WAF/CN=M-WAF Agent CA"
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
CN=M-WAF Manager
[req_ext]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF
  if is_ip_address "$manager_host"; then
    printf 'IP.2=%s\n' "$manager_host" >> "$tls_config"
  elif [ "$manager_host" != "localhost" ]; then
    printf 'DNS.2=%s\n' "$manager_host" >> "$tls_config"
  fi
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$secrets_dir/mwaf_tls_key.pem"
  openssl req -new -sha256 -key "$secrets_dir/mwaf_tls_key.pem" -out "$secrets_dir/mwaf_tls.csr" -config "$tls_config"
  openssl x509 -req -sha256 -in "$secrets_dir/mwaf_tls.csr" -CA "$secrets_dir/mwaf_ca_cert.pem" -CAkey "$secrets_dir/mwaf_ca_key.pem" -CAcreateserial -out "$secrets_dir/mwaf_tls_cert.pem" -days 825 -extfile "$tls_config" -extensions req_ext
  rm -f "$secrets_dir/mwaf_tls.csr" "$secrets_dir/mwaf_ca_cert.srl"
fi

openssl verify -CAfile "$secrets_dir/mwaf_ca_cert.pem" "$secrets_dir/mwaf_tls_cert.pem" >/dev/null || { echo "TLS certificate is not signed by the configured M-WAF CA" >&2; exit 1; }
if is_ip_address "$manager_host"; then
  openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -checkip "$manager_host" >/dev/null || echo "WARNING: existing TLS certificate does not include IP SAN $manager_host; it was not replaced" >&2
else
  openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -checkhost "$manager_host" >/dev/null || echo "WARNING: existing TLS certificate does not include DNS SAN $manager_host; it was not replaced" >&2
fi
if ! certificate_is_p256 "$secrets_dir/mwaf_ca_cert.pem"; then
  echo "WARNING: existing M-WAF CA is not ECDSA P-256 and may be incompatible with some browsers; it was not replaced" >&2
fi
if ! certificate_is_p256 "$secrets_dir/mwaf_tls_cert.pem"; then
  echo "WARNING: existing TLS certificate is not ECDSA P-256 and may be incompatible with some browsers; it was not replaced" >&2
fi

for compose_secret in \
  mariadb_app_password mariadb_root_password mwaf_session_key \
  mwaf_policy_signing_key.pem mwaf_policy_signing_public.pem \
  mwaf_ca_key.pem mwaf_ca_cert.pem mwaf_tls_key.pem mwaf_tls_cert.pem
do
  chmod 0644 "$secrets_dir/$compose_secret"
done
echo "Prepared M-WAF deployment secrets for the non-root Manager without overwriting existing files."
echo "Open the Admin UI to create the first system administrator."
