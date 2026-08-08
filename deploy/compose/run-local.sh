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

requested_admin_port=${MWAF_ADMIN_PORT:-}
requested_admin_bind=${MWAF_DEV_ADMIN_BIND:-}
requested_public_url=${MWAF_PUBLIC_URL:-}
requested_dev_bundle_image=${MWAF_DEV_BUNDLE_IMAGE:-}
set -a
. "$script_dir/.env"
set +a
[ -z "$requested_admin_port" ] || export MWAF_ADMIN_PORT="$requested_admin_port"
[ -z "$requested_admin_bind" ] || export MWAF_DEV_ADMIN_BIND="$requested_admin_bind"
[ -z "$requested_public_url" ] || export MWAF_PUBLIC_URL="$requested_public_url"
[ -z "$requested_dev_bundle_image" ] || export MWAF_DEV_BUNDLE_IMAGE="$requested_dev_bundle_image"

admin_port=${MWAF_ADMIN_PORT:-8443}

valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_port "$admin_port" || { echo "MWAF_ADMIN_PORT must be between 1 and 65535" >&2; exit 1; }

runtime_root=${MWAF_DEV_RUNTIME_DIR:-$repository_root/.local/mwaf-manager}
mkdir -p "$runtime_root/artifacts"

bundle_complete() {
  [ -f "$1/bundle-manifest.json" ] && [ -f "$1/bundle-manifest.sig" ] && [ -f "$2" ]
}

bundle_schema() {
  sed -n 's/^[[:space:]]*"schema_version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*$/\1/p' "$1/bundle-manifest.json" | sed -n '1p'
}

dist_bundle_root="$repository_root/dist/bundle"
dist_bundle_public_key="$repository_root/dist/package-signing.pub"
bundle_root="$dist_bundle_root"
bundle_public_key="$dist_bundle_public_key"
bundle_available=0
dist_bundle_schema=0
if bundle_complete "$dist_bundle_root" "$dist_bundle_public_key"; then
  bundle_available=1
  dist_bundle_schema=$(bundle_schema "$dist_bundle_root")
  dist_bundle_schema=${dist_bundle_schema:-0}
fi

# Local development follows the newest published signed bundle by default.
# A specific immutable release can be selected only through
# MWAF_DEV_BUNDLE_IMAGE. A checkout bundle remains an offline fallback.
manager_image=${MWAF_DEV_BUNDLE_IMAGE:-ghcr.io/fhwang0926/m-waf-manager:latest}
echo "Refreshing the signed development bundle from $manager_image"
if docker pull --platform linux/amd64 "$manager_image"; then
  image_id=$(docker image inspect --format '{{.Id}}' "$manager_image")
  image_id=${image_id#sha256:}
  case "$image_id" in
    ''|*[!A-Fa-f0-9]*) echo "Manager image returned an invalid image ID" >&2; exit 1 ;;
  esac
  cache_root="$runtime_root/bundle-cache/$image_id"
  cache_bundle_root="$cache_root/bundle"
  cache_bundle_public_key="$cache_root/package-signing.pub"
  if ! bundle_complete "$cache_bundle_root" "$cache_bundle_public_key"; then
    mkdir -p "$runtime_root/bundle-cache"
    if [ -e "$cache_root" ]; then
      rm -rf "$cache_root"
    fi
    bundle_staging=$(mktemp -d "$runtime_root/bundle-cache/.extract.XXXXXX")
    bundle_container=
    cleanup_bundle_extract() {
      if [ -n "${bundle_container:-}" ]; then
        docker rm "$bundle_container" >/dev/null 2>&1 || true
      fi
      if [ -n "${bundle_staging:-}" ]; then
        rm -rf "$bundle_staging"
      fi
    }
    trap cleanup_bundle_extract EXIT INT TERM
    bundle_container=$(docker create --platform linux/amd64 "$manager_image")
    mkdir -p "$bundle_staging/bundle"
    docker cp "$bundle_container:/opt/mwaf/bundles/current/." "$bundle_staging/bundle"
    docker cp "$bundle_container:/etc/mwaf-manager/package-signing.pub" "$bundle_staging/package-signing.pub"
    docker rm "$bundle_container" >/dev/null
    bundle_container=
    bundle_complete "$bundle_staging/bundle" "$bundle_staging/package-signing.pub" || { echo "Manager image bundle is incomplete" >&2; exit 1; }
    mv "$bundle_staging" "$cache_root"
    bundle_staging=
  fi
  image_bundle_schema=$(bundle_schema "$cache_bundle_root")
  image_bundle_schema=${image_bundle_schema:-0}
  bundle_root="$cache_bundle_root"
  bundle_public_key="$cache_bundle_public_key"
  bundle_available=1
  echo "Using latest signed schema v${image_bundle_schema} development bundle from $manager_image"
elif [ "$bundle_available" -eq 1 ]; then
  echo "Could not refresh the latest signed development bundle; using local schema v${dist_bundle_schema} fallback" >&2
else
  echo "Latest tagged release bundle is unavailable; starting Manager development without package installation APIs" >&2
fi

if [ "$bundle_available" -eq 1 ]; then
  for required in "$bundle_root/bundle-manifest.json" "$bundle_root/bundle-manifest.sig" "$bundle_public_key"
  do
    [ -f "$required" ] || { echo "Local package bundle is unavailable: $required" >&2; exit 1; }
  done
fi

docker compose --project-name "$compose_project" --env-file "$script_dir/.env" -f "$script_dir/compose.yaml" -f "$script_dir/compose.local.yaml" up -d --wait --wait-timeout 60 mariadb

unset MWAF_DB_DSN MWAF_DB_PASSWORD
export MWAF_ADMIN_ADDR="${MWAF_DEV_ADMIN_BIND:-127.0.0.1}:$admin_port"
case "${MWAF_PUBLIC_URL:-}" in
  ""|https://localhost:8443|https://localhost:9443) export MWAF_PUBLIC_URL="https://localhost:$admin_port" ;;
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
export MWAF_DEV_LIVE_RELOAD=true

echo "Starting local M-WAF Admin UI at https://localhost:$admin_port"
echo "Agent requests use the same Manager URL at $MWAF_PUBLIC_URL"
echo "Go, template, CSS, and JavaScript changes are applied automatically."
echo "Press Ctrl-C to stop Manager. Run 'make dev-down' to stop local MariaDB."
exec sh "$script_dir/watch-manager.sh" "$repository_root" "$runtime_root/mwaf-manager-dev"
