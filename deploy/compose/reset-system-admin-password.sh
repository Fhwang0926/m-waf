#!/bin/sh
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
env_file=${MWAF_ENV_FILE:-$script_dir/.env}
compose_file="$script_dir/compose.yaml"

usage() {
  cat <<'EOF'
Usage: deploy/compose/reset-system-admin-password.sh USERNAME PASSWORD_FILE

Resets one active system-administrator password through the Manager application.
The password file must contain exactly one line with 12 to 256 characters.
EOF
}

fail() {
  echo "Password reset error: $*" >&2
  exit 1
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac
[ "$#" -eq 2 ] || { usage >&2; exit 2; }

username=$1
password_file=$2
[ -f "$env_file" ] || fail "deployment environment not found: $env_file"
[ -s "$password_file" ] || fail "password file is missing or empty: $password_file"
command -v docker >/dev/null 2>&1 || fail "docker is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is required"

manager_container=$(docker compose --env-file "$env_file" -f "$compose_file" ps -q manager)
[ -n "$manager_container" ] || fail "Manager container is not running; start or update the deployed stack first"
manager_status=$(docker inspect --format '{{.State.Status}}' "$manager_container")
[ "$manager_status" = running ] || fail "Manager container is not running: $manager_status"
reset_supported=$(docker inspect --format '{{index .Config.Labels "io.mwaf.feature.system-admin-password-reset"}}' "$manager_container")
[ "$reset_supported" = true ] || fail "deployed Manager image does not support password recovery; deploy an image containing the reset command first"

database_container=$(docker compose --env-file "$env_file" -f "$compose_file" ps -q mariadb)
[ -n "$database_container" ] || fail "MariaDB container is not running; start the deployed stack first"
database_status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$database_container")
case "$database_status" in
  healthy|running) ;;
  *) fail "MariaDB container is not ready: $database_status" ;;
esac

docker compose --env-file "$env_file" -f "$compose_file" run --rm --no-deps -T manager \
  reset-system-admin-password --username "$username" --password-stdin < "$password_file"
