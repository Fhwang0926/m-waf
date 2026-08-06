#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_project=${MWAF_DEV_COMPOSE_PROJECT:-mwaf-local}

case "${1:-run}" in
  down)
    command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
    env_file="$script_dir/.env"
    [ -f "$env_file" ] || env_file="$script_dir/.env.example"
    exec docker compose --project-name "$compose_project" --env-file "$env_file" -f "$script_dir/compose.yaml" -f "$script_dir/compose.local.yaml" down
    ;;
  db-logs)
    command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
    env_file="$script_dir/.env"
    [ -f "$env_file" ] || env_file="$script_dir/.env.example"
    exec docker compose --project-name "$compose_project" --env-file "$env_file" -f "$script_dir/compose.yaml" -f "$script_dir/compose.local.yaml" logs -f --tail=200 mariadb
    ;;
  run)
    ;;
  *)
    echo "usage: $0 [run|down|db-logs]" >&2
    exit 2
    ;;
esac

command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Go 1.26 or newer is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required" >&2; exit 1; }

"$script_dir/prepare.sh"

set -a
. "$script_dir/.env"
set +a

admin_port=${MWAF_ADMIN_PORT:-8443}
agent_port=${MWAF_AGENT_PORT:-10443}

valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_port "$admin_port" || { echo "MWAF_ADMIN_PORT must be between 1 and 65535" >&2; exit 1; }
valid_port "$agent_port" || { echo "MWAF_AGENT_PORT must be between 1 and 65535" >&2; exit 1; }

runtime_root=${MWAF_DEV_RUNTIME_DIR:-$repository_root/.local/mwaf-manager}
mkdir -p "$runtime_root/artifacts"

bundle_root="$repository_root/dist/bundle"
bundle_public_key="$repository_root/dist/package-signing.pub"
bundle_available=1
if [ ! -f "$bundle_root/bundle-manifest.json" ] || [ ! -f "$bundle_root/bundle-manifest.sig" ] || [ ! -f "$bundle_public_key" ]; then
  bundle_root="$runtime_root/bundle"
  bundle_public_key="$runtime_root/package-signing.pub"
  mkdir -p "$bundle_root"
  if [ ! -f "$bundle_root/bundle-manifest.json" ] || [ ! -f "$bundle_root/bundle-manifest.sig" ] || [ ! -f "$bundle_public_key" ]; then
    manager_image=${MWAF_BUNDLE_IMAGE:-${MWAF_DEV_BUNDLE_IMAGE:-ghcr.io/fhwang0926/m-waf-manager:latest}}
    echo "Local package bundle is missing; extracting it from $manager_image"
    if docker pull --platform linux/amd64 "$manager_image"; then
      bundle_container=$(docker create --platform linux/amd64 "$manager_image")
      cleanup_bundle_container() {
        if [ -n "${bundle_container:-}" ]; then
          docker rm "$bundle_container" >/dev/null 2>&1 || true
        fi
      }
      trap cleanup_bundle_container EXIT INT TERM
      docker cp "$bundle_container:/opt/mwaf/bundles/current/." "$bundle_root"
      docker cp "$bundle_container:/etc/mwaf-manager/package-signing.pub" "$bundle_public_key"
      docker rm "$bundle_container" >/dev/null
      bundle_container=
    else
      bundle_available=0
      echo "Tagged release bundle is not available yet; starting Manager development without package installation APIs" >&2
    fi
  fi
fi

if [ "$bundle_available" -eq 1 ]; then
  for required in "$bundle_root/bundle-manifest.json" "$bundle_root/bundle-manifest.sig" "$bundle_public_key"
  do
    [ -f "$required" ] || { echo "Local package bundle is unavailable: $required" >&2; exit 1; }
  done
fi

docker compose --project-name "$compose_project" --env-file "$script_dir/.env" -f "$script_dir/compose.yaml" -f "$script_dir/compose.local.yaml" up -d mariadb

unset MWAF_DB_DSN MWAF_DB_PASSWORD
export MWAF_ADMIN_ADDR="${MWAF_DEV_ADMIN_BIND:-127.0.0.1}:$admin_port"
export MWAF_AGENT_ADDR="${MWAF_DEV_AGENT_BIND:-127.0.0.1}:$agent_port"
case "${MWAF_AGENT_PUBLIC_URL:-}" in
  ""|https://localhost:9443) export MWAF_AGENT_PUBLIC_URL="https://localhost:$agent_port" ;;
esac
export MWAF_DB_HOST=127.0.0.1
export MWAF_DB_PORT=${MWAF_DEV_DB_PORT:-3306}
export MWAF_DB_NAME=${MWAF_DB_NAME:-mwaf}
export MWAF_DB_USER=${MWAF_DB_USER:-mwaf}
export MWAF_DB_PASSWORD_FILE="$script_dir/secrets/mariadb_app_password"
export MWAF_DB_MIGRATE=true
export MWAF_SESSION_KEY_FILE="$script_dir/secrets/mwaf_session_key"
export MWAF_TLS_CERT="$script_dir/secrets/mwaf_tls_cert.pem"
export MWAF_TLS_KEY="$script_dir/secrets/mwaf_tls_key.pem"
export MWAF_AGENT_CA_CERT="$script_dir/secrets/mwaf_ca_cert.pem"
export MWAF_AGENT_CA_KEY="$script_dir/secrets/mwaf_ca_key.pem"
export MWAF_POLICY_SIGNING_KEY="$script_dir/secrets/mwaf_policy_signing_key.pem"
export MWAF_POLICY_SIGNING_PUBLIC="$script_dir/secrets/mwaf_policy_signing_public.pem"
export MWAF_BUNDLE_ROOT="$bundle_root"
export MWAF_BUNDLE_PUBLIC_KEY="$bundle_public_key"
if [ "$bundle_available" -eq 1 ]; then
  export MWAF_BUNDLE_REQUIRED=true
else
  export MWAF_BUNDLE_REQUIRED=false
fi
export MWAF_ARTIFACT_ROOT="$runtime_root/artifacts"

echo "Starting local M-WAF Admin UI at https://localhost:$admin_port"
echo "Agent API is available at $MWAF_AGENT_PUBLIC_URL"
echo "Press Ctrl-C to stop Manager. Run 'make dev-down' to stop local MariaDB."
cd "$repository_root"
exec go run ./cmd/mwaf-manager
