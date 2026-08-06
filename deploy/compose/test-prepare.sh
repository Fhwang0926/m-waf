#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prepare_script="$script_dir/prepare.sh"
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT INT TERM

check_case() {
  case_name=$1
  manager_host=$2
  runtime_dir="$test_root/$case_name"
  env_file="$runtime_dir/.env"
  secrets_dir="$runtime_dir/secrets"
  mkdir -p "$runtime_dir"
  printf 'MWAF_MANAGER_HOST=%s\n' "$manager_host" > "$env_file"

  MWAF_ENV_FILE="$env_file" MWAF_SECRETS_DIR="$secrets_dir" "$prepare_script" >/dev/null

  [ "$(stat -c '%a' "$secrets_dir")" = "700" ]
  for compose_secret in \
    mariadb_app_password mariadb_root_password mwaf_session_key \
    mwaf_policy_signing_key.pem mwaf_policy_signing_public.pem \
    mwaf_ca_key.pem mwaf_ca_cert.pem mwaf_tls_key.pem mwaf_tls_cert.pem
  do
    [ "$(stat -c '%a' "$secrets_dir/$compose_secret")" = "644" ]
  done

  openssl verify -CAfile "$secrets_dir/mwaf_ca_cert.pem" "$secrets_dir/mwaf_tls_cert.pem" >/dev/null
  openssl x509 -in "$secrets_dir/mwaf_ca_cert.pem" -noout -text | grep -q 'Public Key Algorithm: id-ecPublicKey'
  openssl x509 -in "$secrets_dir/mwaf_ca_cert.pem" -noout -text | grep -q 'ASN1 OID: prime256v1'
  openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -text | grep -q 'Public Key Algorithm: id-ecPublicKey'
  openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -text | grep -q 'ASN1 OID: prime256v1'
  openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -checkhost localhost >/dev/null
  case "$manager_host" in
    *:*) openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -checkip "$manager_host" >/dev/null ;;
    *[!0-9.]*) openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -checkhost "$manager_host" >/dev/null ;;
    *) openssl x509 -in "$secrets_dir/mwaf_tls_cert.pem" -noout -checkip "$manager_host" >/dev/null ;;
  esac

  before=$(sha256sum "$secrets_dir"/mariadb_app_password "$secrets_dir"/mwaf_*.pem "$secrets_dir"/mwaf_session_key)
  MWAF_ENV_FILE="$env_file" MWAF_SECRETS_DIR="$secrets_dir" "$prepare_script" >/dev/null
  after=$(sha256sum "$secrets_dir"/mariadb_app_password "$secrets_dir"/mwaf_*.pem "$secrets_dir"/mwaf_session_key)
  [ "$before" = "$after" ]
}

check_case ipv4 192.168.7.200
check_case dns manager.example.com

echo "prepare.sh secret permissions, ECDSA certificates, SANs, and non-overwrite behavior are valid."
