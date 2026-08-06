#!/bin/sh
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
base_compose="$repo_root/deploy/compose/compose.yaml"
e2e_compose="$script_dir/compose.yaml"
prepare_script="$repo_root/deploy/compose/prepare.sh"
project_name=mwaf-e2e
runtime_dir=${MWAF_E2E_RUNTIME_DIR:-$repo_root/.local/mwaf-e2e}
case "$runtime_dir" in
  /*) ;;
  *) runtime_dir="$repo_root/$runtime_dir" ;;
esac
env_file="$runtime_dir/compose.env"
secrets_dir="$runtime_dir/secrets"
cookie_jar="$runtime_dir/admin.cookies"
apache_enrollment_response="$runtime_dir/customer-apache-enrollment-$$.json"
nginx_enrollment_response="$runtime_dir/customer-nginx-enrollment-$$.json"
lock_dir="$runtime_dir/run.lock"
lock_acquired=0
result_dir=""

stored_value() {
  key=$1
  [ -f "$env_file" ] || return 0
  sed -n "s/^${key}=//p" "$env_file" | tail -n 1
}

manager_image=${MWAF_E2E_MANAGER_IMAGE:-$(stored_value MWAF_MANAGER_IMAGE)}
manager_image=${manager_image:-ghcr.io/fhwang0926/m-waf-manager:latest}
admin_port=${MWAF_E2E_ADMIN_PORT:-$(stored_value MWAF_ADMIN_PORT)}
admin_port=${admin_port:-8443}
agent_port=${MWAF_E2E_AGENT_PORT:-$(stored_value MWAF_AGENT_PORT)}
agent_port=${agent_port:-10443}
apache_port=${MWAF_E2E_APACHE_PORT:-$(stored_value MWAF_E2E_APACHE_PORT)}
apache_port=${apache_port:-18080}
nginx_port=${MWAF_E2E_NGINX_PORT:-$(stored_value MWAF_E2E_NGINX_PORT)}
nginx_port=${nginx_port:-18081}
web_bind=${MWAF_E2E_WEB_BIND:-$(stored_value MWAF_E2E_WEB_BIND)}
web_bind=${web_bind:-127.0.0.1}
enterprise_name=${MWAF_E2E_ENTERPRISE_NAME:-mwaf-e2e}
group_name=${MWAF_E2E_GROUP_NAME:-mwaf-e2e-webservers}
policy_name=${MWAF_E2E_POLICY_NAME:-mwaf-e2e-block-policy}
admin_display_name=${MWAF_E2E_ADMIN_DISPLAY_NAME:-M-WAF E2E Administrator}
admin_url="https://localhost:$admin_port"
agent_url="https://manager:$agent_port"

usage() {
  cat <<'EOF'
Usage: deploy/e2e/run.sh COMMAND [OPTIONS]

Commands:
  all       Deploy Manager and customer containers, then verify enrollment and policy flow
  up        Deploy Manager and customer containers and enroll both Agents
  verify    Verify group policy deployment, HTTP blocking, exclusion, and event collection
  status    Show container status
  logs      Follow container logs
  down      Remove containers and networks while preserving named volumes and runtime secrets

Options:
  --manager-image IMAGE   Tagged or digest-pinned Manager image
  --admin-port PORT       Host Admin HTTPS port (default: 8443)
  --agent-port PORT       Host Agent HTTPS port (default: 10443)
  --apache-port PORT      Host Apache test port (default: 18080)
  --nginx-port PORT       Host Nginx test port (default: 18081)
  -h, --help              Show this help

Set MWAF_E2E_ADMIN_PASSWORD before the first run to choose the generated system
administrator password. If omitted, a random password is stored with mode 0600
under .local/mwaf-e2e and is never printed.
EOF
}

fail() {
  echo "E2E error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

compose() {
  docker compose --project-name "$project_name" --env-file "$env_file" -f "$base_compose" -f "$e2e_compose" "$@"
}

cleanup_sensitive_files() {
  rm -f "$apache_enrollment_response" "$nginx_enrollment_response"
}

acquire_lock() {
  [ "$lock_acquired" -eq 0 ] || return 0
  umask 077
  mkdir -p "$runtime_dir"
  if ! mkdir "$lock_dir" 2>/dev/null; then
    fail "another E2E mutation is running; inspect $lock_dir"
  fi
  printf '%s\n' "$$" > "$lock_dir/pid"
  lock_acquired=1
}

release_lock() {
  [ "$lock_acquired" -eq 1 ] || return 0
  rm -f "$lock_dir/pid"
  rmdir "$lock_dir" 2>/dev/null || true
  lock_acquired=0
}

collect_diagnostics() {
  [ -n "$result_dir" ] || return 0
  mkdir -p "$result_dir"
  compose ps --all > "$result_dir/compose-ps.txt" 2>&1 || true
  compose logs --no-color --tail=500 > "$result_dir/compose.log" 2>&1 || true
}

on_exit() {
  status=$?
  set +e
  cleanup_sensitive_files
  if [ "$status" -ne 0 ] && [ -n "$result_dir" ]; then
    printf 'FAILED\n' > "$result_dir/status.txt"
    collect_diagnostics
    echo "E2E diagnostics: $result_dir" >&2
  fi
  release_lock
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

command_name=${1:-all}
case "$command_name" in
  all|up|verify|status|logs|down) shift ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; fail "unknown command: $command_name" ;;
esac

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manager-image) [ "$#" -ge 2 ] || fail "--manager-image requires a value"; manager_image=$2; shift 2 ;;
    --admin-port) [ "$#" -ge 2 ] || fail "--admin-port requires a value"; admin_port=$2; shift 2 ;;
    --agent-port) [ "$#" -ge 2 ] || fail "--agent-port requires a value"; agent_port=$2; shift 2 ;;
    --apache-port) [ "$#" -ge 2 ] || fail "--apache-port requires a value"; apache_port=$2; shift 2 ;;
    --nginx-port) [ "$#" -ge 2 ] || fail "--nginx-port requires a value"; nginx_port=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

admin_url="https://localhost:$admin_port"
agent_url="https://manager:$agent_port"

preflight_common() {
  require_command docker
  docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is required"
  docker info >/dev/null 2>&1 || fail "Docker daemon is not available"
}

preflight_full() {
  preflight_common
  [ "$(uname -s)" = Linux ] || fail "the systemd customer-container test requires a dedicated Linux host"
  case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "the signed customer packages currently require x86_64/amd64" ;;
  esac
  require_command curl
  require_command jq
  require_command openssl
  require_command awk
  require_command sed
  for port in "$admin_port" "$agent_port" "$apache_port" "$nginx_port"; do
    valid_port "$port" || fail "invalid port: $port"
  done
  [ "$admin_port" != "$agent_port" ] || fail "Admin and Agent ports must differ"
  [ "$apache_port" != "$nginx_port" ] || fail "Apache and Nginx ports must differ"
  seen_ports=" "
  for port in "$admin_port" "$agent_port" "$apache_port" "$nginx_port"; do
    case "$seen_ports" in
      *" $port "*) fail "host ports must be unique: $port is repeated" ;;
    esac
    seen_ports="$seen_ports$port "
  done
  [ -n "$manager_image" ] || fail "Manager image is required"
  case "$manager_image" in
    *[!A-Za-z0-9_./:@+-]*) fail "Manager image contains unsupported characters" ;;
  esac
  case "$runtime_dir" in
    *" "*|*"#"*) fail "MWAF_E2E_RUNTIME_DIR must not contain spaces or #" ;;
  esac
  if [ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project_name")" ] && command -v ss >/dev/null 2>&1; then
    listening=$(ss -H -ltn 2>/dev/null | awk '{print $4}')
    for port in "$admin_port" "$agent_port" "$apache_port" "$nginx_port"; do
      if printf '%s\n' "$listening" | grep -Eq "[:.]${port}$"; then
        fail "host port $port is already in use"
      fi
    done
  fi
  if [ "$manager_image" = ghcr.io/fhwang0926/m-waf-manager:latest ]; then
    echo "Warning: latest is mutable; use --manager-image with a release tag or digest for reproducible evidence." >&2
  fi
}

prepare_runtime() {
  umask 077
  mkdir -p "$runtime_dir" "$secrets_dir" "$runtime_dir/results"

  username_file="$runtime_dir/admin.username"
  password_file="$runtime_dir/admin.password"
  if [ -e "$username_file" ] || [ -e "$password_file" ]; then
    [ -s "$username_file" ] && [ -s "$password_file" ] || fail "administrator credential files are incomplete in $runtime_dir"
  else
    admin_username=${MWAF_E2E_ADMIN_USERNAME:-mwaf-e2e-admin}
    admin_password=${MWAF_E2E_ADMIN_PASSWORD:-$(openssl rand -hex 24)}
    printf '%s' "$admin_username" | grep -Eq '^[A-Za-z0-9._-]{3,128}$' || fail "MWAF_E2E_ADMIN_USERNAME is invalid"
    [ "${#admin_password}" -ge 12 ] || fail "MWAF_E2E_ADMIN_PASSWORD must be at least 12 characters"
    printf '%s\n' "$admin_username" > "$username_file"
    printf '%s' "$admin_password" > "$password_file"
    chmod 0600 "$username_file" "$password_file"
  fi

  cat > "$env_file" <<EOF
MARIADB_IMAGE=mariadb:11.8.6@sha256:78a5047d3ba33975f183f183c2464cc7f1eab13ec8667e57cc9a5821d6da7577
MWAF_MANAGER_IMAGE=$manager_image
MWAF_DB_NAME=mwaf
MWAF_DB_USER=mwaf
MWAF_ADMIN_BIND=127.0.0.1
MWAF_ADMIN_PORT=$admin_port
MWAF_AGENT_BIND=127.0.0.1
MWAF_AGENT_PORT=$agent_port
MWAF_MANAGER_HOST=manager
MWAF_AGENT_PUBLIC_URL=$agent_url
MWAF_EVENT_RETENTION=720h
MWAF_POLICY_SYNC_INTERVAL=15m
MWAF_E2E_RUNTIME_DIR=$runtime_dir
MWAF_E2E_WEB_BIND=$web_bind
MWAF_E2E_APACHE_PORT=$apache_port
MWAF_E2E_NGINX_PORT=$nginx_port
EOF
  chmod 0600 "$env_file"

  MWAF_ENV_FILE="$env_file" MWAF_SECRETS_DIR="$secrets_dir" "$prepare_script"
  compose config --quiet
}

wait_manager() {
  deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl --fail --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" "$admin_url/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  fail "Manager did not become ready within 180 seconds"
}

admin_get() {
  path=$1
  output=$2
  curl --fail --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
    --cookie "$cookie_jar" --cookie-jar "$cookie_jar" "$admin_url$path" -o "$output"
}

extract_csrf() {
  sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$1" | tail -n 1
}

login_admin() {
  setup_page="$runtime_dir/setup.html"
  admin_username=$(sed -n '1p' "$runtime_dir/admin.username")
  curl --silent --show-error --location --cacert "$secrets_dir/mwaf_ca_cert.pem" \
    --cookie "$cookie_jar" --cookie-jar "$cookie_jar" "$admin_url/setup" -o "$setup_page"

  if grep -q 'FIRST-TIME SETUP' "$setup_page"; then
    csrf=$(extract_csrf "$setup_page")
    [ -n "$csrf" ] || fail "could not read setup CSRF token"
    status=$(curl --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
      --cookie "$cookie_jar" --cookie-jar "$cookie_jar" -o "$runtime_dir/setup-result.html" -w '%{http_code}' \
      --data-urlencode "csrf=$csrf" --data-urlencode "username=$admin_username" \
      --data-urlencode "display_name=$admin_display_name" --data-urlencode "password@$runtime_dir/admin.password" \
      --data-urlencode "password_confirm@$runtime_dir/admin.password" "$admin_url/setup")
    [ "$status" = 303 ] || fail "system administrator setup returned HTTP $status"
  else
    status=$(curl --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
      --cookie "$cookie_jar" --cookie-jar "$cookie_jar" -o "$runtime_dir/login-result.html" -w '%{http_code}' \
      --data-urlencode "username=$admin_username" --data-urlencode "password@$runtime_dir/admin.password" "$admin_url/login")
    [ "$status" = 303 ] || fail "administrator login returned HTTP $status; restore $runtime_dir/admin.password or provide the original runtime directory"
  fi
  admin_get / "$runtime_dir/dashboard.html"
}

extract_enterprise_id() {
  file=$1
  awk -v target="$enterprise_name" 'BEGIN { RS="<tr>" }
    index($0, "<td>" target "</td>") {
      if (match($0, /<span class="mono">[^<]+/)) {
        value=substr($0, RSTART, RLENGTH); sub(/^.*>/, "", value); print value; exit
      }
    }' "$file"
}

ensure_enterprise() {
  page="$runtime_dir/enterprises.html"
  admin_get /enterprises "$page"
  enterprise_id=$(extract_enterprise_id "$page")
  if [ -z "$enterprise_id" ]; then
    csrf=$(extract_csrf "$page")
    [ -n "$csrf" ] || fail "could not read enterprise CSRF token"
    status=$(curl --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
      --cookie "$cookie_jar" --cookie-jar "$cookie_jar" -o "$runtime_dir/enterprise-result.html" -w '%{http_code}' \
      --data-urlencode "csrf=$csrf" --data-urlencode "name=$enterprise_name" "$admin_url/enterprises")
    [ "$status" = 303 ] || fail "enterprise creation returned HTTP $status"
    admin_get /enterprises "$page"
    enterprise_id=$(extract_enterprise_id "$page")
  fi
  [ -n "$enterprise_id" ] || fail "could not resolve the E2E enterprise ID"
}

create_enrollment_token() {
  service=$1
  label=$2
  response_file=$3
  page="$runtime_dir/enrollment.html"
  admin_get /enrollments/new "$page"
  csrf=$(extract_csrf "$page")
  [ -n "$csrf" ] || fail "could not read enrollment CSRF token"
  payload=$(jq -cn --arg enterprise_id "$enterprise_id" --arg label "$label" '{enterprise_id:$enterprise_id,label:$label}')
  status=$(curl --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
    --cookie "$cookie_jar" --cookie-jar "$cookie_jar" -o "$response_file" -w '%{http_code}' \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" --data "$payload" \
    "$admin_url/api/v1/enrollment-tokens")
  [ "$status" = 201 ] || fail "enrollment token creation for $service returned HTTP $status"
  jq -er '.token' "$response_file"
}

wait_customer_web() {
  service=$1
  deadline=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if compose exec -T "$service" curl --fail --silent http://127.0.0.1/ >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  fail "$service web server did not become ready within 120 seconds"
}

install_customer_agent() {
  service=$1
  web_server=$2
  label=$3
  response_file=$4
  module_package="mwaf-modsecurity-$web_server"

  wait_customer_web "$service"
  if compose exec -T "$service" dpkg-query -W mwaf-agent "$module_package" >/dev/null 2>&1; then
    compose exec -T "$service" systemctl enable --now mwaf-agent.service >/dev/null
    return 0
  fi

  token=$(create_enrollment_token "$service" "$label" "$response_file")
  printf '%s\n' "$token" | compose exec -T "$service" sh -c 'umask 077; cat > /run/mwaf-e2e-token'
  token=""
  rm -f "$response_file"
  compose exec -T "$service" sh -c '
    set -eu
    trap '\''rm -f /run/mwaf-e2e-token /run/mwaf-install.sh'\'' EXIT INT TERM
    curl --fail --silent --show-error --cacert /run/secrets/mwaf_manager_ca "$1/bootstrap/v1/install.sh" -o /run/mwaf-install.sh
    sh /run/mwaf-install.sh --manager "$1" --token "$(cat /run/mwaf-e2e-token)" --ca /run/secrets/mwaf_manager_ca --webserver "$2"
  ' mwaf-e2e-install "$agent_url" "$web_server"
}

fetch_servers() {
  admin_get /api/v1/servers "$runtime_dir/servers.json"
}

server_id_for() {
  jq -er --arg name "$1" '.items | map(select(.Name == $name and .Revoked == false)) | first | .ID' "$runtime_dir/servers.json"
}

wait_agents_online() {
  deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    fetch_servers
    apache_online=$(jq -r --arg name mwaf-e2e-apache '[.items[] | select(.Name == $name and .Revoked == false and .Status == "ONLINE")] | length' "$runtime_dir/servers.json")
    nginx_online=$(jq -r --arg name mwaf-e2e-nginx '[.items[] | select(.Name == $name and .Revoked == false and .Status == "ONLINE")] | length' "$runtime_dir/servers.json")
    if [ "$apache_online" -gt 0 ] && [ "$nginx_online" -gt 0 ]; then
      apache_server_id=$(server_id_for mwaf-e2e-apache)
      nginx_server_id=$(server_id_for mwaf-e2e-nginx)
      compose exec -T customer-apache rm -f /etc/mwaf-agent/enrollment.token >/dev/null 2>&1 || true
      compose exec -T customer-nginx rm -f /etc/mwaf-agent/enrollment.token >/dev/null 2>&1 || true
      return 0
    fi
    sleep 5
  done
  fail "both Agents did not become ONLINE within 180 seconds"
}

extract_group_id() {
  file=$1
  awk -v target="$group_name" 'BEGIN { RS="<section class=\"panel\">" }
    index($0, "value=\"" target "\"") {
      if (match($0, /action="\/groups\/[^\"]+"/)) {
        value=substr($0, RSTART, RLENGTH); sub(/^action="\/groups\//, "", value); sub(/"$/, "", value); print value; exit
      }
    }' "$file"
}

ensure_group() {
  page="$runtime_dir/groups.html"
  admin_get /groups "$page"
  group_id=$(extract_group_id "$page")
  csrf=$(extract_csrf "$page")
  [ -n "$csrf" ] || fail "could not read group CSRF token"
  if [ -z "$group_id" ]; then
    status=$(curl --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
      --cookie "$cookie_jar" --cookie-jar "$cookie_jar" -o "$runtime_dir/group-result.html" -w '%{http_code}' \
      --data-urlencode "csrf=$csrf" --data-urlencode "enterprise_id=$enterprise_id" \
      --data-urlencode "name=$group_name" --data-urlencode "server_ids=$apache_server_id" \
      --data-urlencode "server_ids=$nginx_server_id" "$admin_url/groups")
    [ "$status" = 303 ] || fail "group creation returned HTTP $status"
    admin_get /groups "$page"
    group_id=$(extract_group_id "$page")
  else
    status=$(curl --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
      --cookie "$cookie_jar" --cookie-jar "$cookie_jar" -o "$runtime_dir/group-result.html" -w '%{http_code}' \
      --data-urlencode "csrf=$csrf" --data-urlencode "enterprise_id=$enterprise_id" \
      --data-urlencode "name=$group_name" --data-urlencode "server_ids=$apache_server_id" \
      --data-urlencode "server_ids=$nginx_server_id" "$admin_url/groups/$group_id")
    [ "$status" = 303 ] || fail "group update returned HTTP $status"
  fi
  [ -n "$group_id" ] || fail "could not resolve the E2E group ID"
}

ensure_policy() {
  page="$runtime_dir/policies.html"
  admin_get /policies "$page"
  if grep -Fq "<strong>$policy_name</strong>" "$page"; then
    return 0
  fi
  policy_page="$runtime_dir/policy-new.html"
  admin_get /policies/new "$policy_page"
  csrf=$(extract_csrf "$policy_page")
  [ -n "$csrf" ] || fail "could not read policy CSRF token"
  custom_rule='SecRule REQUEST_URI "@streq /mwaf-e2e-block" "id:100001,phase:1,deny,status:403,log,msg:M-WAF E2E block"'
  status=$(curl --silent --show-error --cacert "$secrets_dir/mwaf_ca_cert.pem" \
    --cookie "$cookie_jar" --cookie-jar "$cookie_jar" -o "$runtime_dir/policy-result.html" -w '%{http_code}' \
    --data-urlencode "csrf=$csrf" --data-urlencode 'template_key=crs-baseline' \
    --data-urlencode "name=$policy_name" --data-urlencode 'description=Container E2E group policy' \
    --data-urlencode "target=group:$group_id" --data-urlencode 'update_strategy=MANUAL' \
    --data-urlencode 'mode=On' --data-urlencode 'paranoia_level=1' --data-urlencode 'inbound_score=5' \
    --data-urlencode 'request_body=on' --data-urlencode 'excluded_paths=/mwaf-e2e-excluded' \
    --data-urlencode "custom_rules=$custom_rule" "$admin_url/policies")
  [ "$status" = 303 ] || fail "policy creation returned HTTP $status"
}

wait_policy_applied() {
  deadline=$(( $(date +%s) + 240 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    fetch_servers
    apache_applied=$(jq -r --arg id "$apache_server_id" '[.items[] | select(.ID == $id and .PolicyDeploymentStatus == "APPLIED")] | length' "$runtime_dir/servers.json")
    nginx_applied=$(jq -r --arg id "$nginx_server_id" '[.items[] | select(.ID == $id and .PolicyDeploymentStatus == "APPLIED")] | length' "$runtime_dir/servers.json")
    if [ "$apache_applied" -gt 0 ] && [ "$nginx_applied" -gt 0 ]; then
      return 0
    fi
    if jq -e --arg aid "$apache_server_id" --arg nid "$nginx_server_id" '.items[] | select((.ID == $aid or .ID == $nid) and .PolicyDeploymentStatus == "FAILED")' "$runtime_dir/servers.json" >/dev/null; then
      jq -r --arg aid "$apache_server_id" --arg nid "$nginx_server_id" '.items[] | select(.ID == $aid or .ID == $nid) | "\(.Name): \(.PolicyDeploymentStatus) \(.PolicyDeploymentDetail)"' "$runtime_dir/servers.json" >&2
      fail "policy deployment failed"
    fi
    sleep 5
  done
  fail "group policy was not APPLIED to both servers within 240 seconds"
}

expect_http_status() {
  expected=$1
  url=$2
  actual=$(curl --silent --show-error -o /dev/null -w '%{http_code}' "$url")
  [ "$actual" = "$expected" ] || fail "$url returned HTTP $actual; expected $expected"
}

wait_block_events() {
  deadline=$(( $(date +%s) + 90 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    admin_get /api/v1/events "$runtime_dir/events.json"
    apache_event=$(jq -r '[.items[] | select(.ServerName == "mwaf-e2e-apache" and .URI == "/mwaf-e2e-block" and .Blocked == true)] | length' "$runtime_dir/events.json")
    nginx_event=$(jq -r '[.items[] | select(.ServerName == "mwaf-e2e-nginx" and .URI == "/mwaf-e2e-block" and .Blocked == true)] | length' "$runtime_dir/events.json")
    if [ "$apache_event" -gt 0 ] && [ "$nginx_event" -gt 0 ]; then
      return 0
    fi
    sleep 3
  done
  fail "blocked events from both customer containers were not collected within 90 seconds"
}

up_stack() {
  preflight_full
  acquire_lock
  prepare_runtime
  echo "Starting isolated Manager and systemd customer containers..."
  compose pull mariadb manager
  compose up -d --build mariadb manager customer-apache customer-nginx
  wait_manager
  login_admin
  ensure_enterprise
  install_customer_agent customer-apache apache mwaf-e2e-apache "$apache_enrollment_response"
  install_customer_agent customer-nginx nginx mwaf-e2e-nginx "$nginx_enrollment_response"
  wait_agents_online
  echo "Manager and both customer Agents are online."
  echo "Admin UI: $admin_url"
  echo "Apache: http://localhost:$apache_port"
  echo "Nginx: http://localhost:$nginx_port"
}

verify_stack() {
  preflight_full
  acquire_lock
  [ -f "$env_file" ] || fail "run the up command first"
  result_dir="$runtime_dir/results/$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mkdir -p "$result_dir"
  wait_manager
  login_admin
  ensure_enterprise
  wait_agents_online
  ensure_group
  ensure_policy
  wait_policy_applied

  expect_http_status 200 "http://127.0.0.1:$apache_port/"
  expect_http_status 200 "http://127.0.0.1:$nginx_port/"
  expect_http_status 200 "http://127.0.0.1:$apache_port/mwaf-e2e-excluded"
  expect_http_status 200 "http://127.0.0.1:$nginx_port/mwaf-e2e-excluded"
  expect_http_status 403 "http://127.0.0.1:$apache_port/mwaf-e2e-block"
  expect_http_status 403 "http://127.0.0.1:$nginx_port/mwaf-e2e-block"
  wait_block_events

  commit=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)
  jq -n \
    --arg status PASS --arg commit "$commit" --arg manager_image "$manager_image" \
    --arg admin_url "$admin_url" --arg apache_server_id "$apache_server_id" \
    --arg nginx_server_id "$nginx_server_id" --arg enterprise_id "$enterprise_id" \
    --arg group_id "$group_id" --arg policy_name "$policy_name" \
    '{status:$status,commit:$commit,manager_image:$manager_image,admin_url:$admin_url,enterprise_id:$enterprise_id,group_id:$group_id,policy_name:$policy_name,servers:{apache:$apache_server_id,nginx:$nginx_server_id},checks:["agents_online","group_policy_applied","benign_200","excluded_path_200","blocked_path_403","blocked_events_collected"]}' \
    > "$result_dir/summary.json"
  printf 'PASS\n' > "$result_dir/status.txt"
  collect_diagnostics
  echo "E2E verification passed. Evidence: $result_dir"
}

case "$command_name" in
  all) up_stack; verify_stack ;;
  up) up_stack ;;
  verify) verify_stack ;;
  status)
    preflight_common
    [ -f "$env_file" ] || fail "E2E runtime has not been prepared"
    compose ps --all
    ;;
  logs)
    preflight_common
    [ -f "$env_file" ] || fail "E2E runtime has not been prepared"
    compose logs -f --tail=200
    ;;
  down)
    preflight_common
    acquire_lock
    [ -f "$env_file" ] || fail "E2E runtime has not been prepared"
    compose down --remove-orphans
    echo "E2E containers were removed. Named volumes and $runtime_dir were preserved."
    ;;
esac
