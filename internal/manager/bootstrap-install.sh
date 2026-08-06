#!/bin/sh
set -eu

manager=""
token=""
ca_file=""
web_server=""
web_server_binary=""
integration_mode="distro"
integration_config=""
audit_log="/var/log/modsecurity/audit.jsonl"
web_group="www-data"
modsecurity_base=""
reload_web_server=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manager) manager=$2; shift 2 ;;
    --token) token=$2; shift 2 ;;
    --ca) ca_file=$2; shift 2 ;;
    --webserver) web_server=$2; shift 2 ;;
    --webserver-bin) web_server_binary=$2; shift 2 ;;
    --integration) integration_mode=$2; shift 2 ;;
    --integration-config) integration_config=$2; shift 2 ;;
    --audit-log) audit_log=$2; shift 2 ;;
    --web-group) web_group=$2; shift 2 ;;
    --modsecurity-base) modsecurity_base=$2; shift 2 ;;
    --reload) reload_web_server=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -n "$manager" ] && [ -n "$token" ] && [ -r "$ca_file" ] || { echo "--manager, --token and readable --ca are required" >&2; exit 2; }
case "$integration_mode" in distro|external) ;; *) echo "--integration must be distro or external" >&2; exit 2 ;; esac
if [ -n "$web_server_binary" ]; then
  [ -n "$web_server" ] || { echo "--webserver is required with --webserver-bin" >&2; exit 2; }
  case "$web_server_binary" in /*) ;; *) echo "--webserver-bin must be an absolute path" >&2; exit 2 ;; esac
  [ -x "$web_server_binary" ] || { echo "web-server control binary is not executable: $web_server_binary" >&2; exit 1; }
fi
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
[ -r /etc/os-release ] || { echo "unsupported OS: /etc/os-release missing" >&2; exit 1; }

. /etc/os-release
os_id=${ID:-unknown}
os_version=${VERSION_ID:-unknown}
case "$(uname -m)" in
  x86_64) architecture=amd64 ;;
  *) echo "unsupported architecture: $(uname -m); this release supports x86_64 only" >&2; exit 1 ;;
esac

has_apache=0
has_nginx=0
if command -v apachectl >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then has_apache=1; fi
if command -v nginx >/dev/null 2>&1; then has_nginx=1; fi
if [ -z "$web_server" ]; then
  if [ "$has_apache" -eq 1 ] && [ "$has_nginx" -eq 1 ]; then
    echo "both Apache and Nginx are installed; pass --webserver apache|nginx" >&2
    exit 1
  elif [ "$has_apache" -eq 1 ]; then
    web_server=apache
  elif [ "$has_nginx" -eq 1 ]; then
    web_server=nginx
  else
    echo "Apache or Nginx must already be installed" >&2
    exit 1
  fi
fi

hash_text() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'; else shasum -a 256 | awk '{print $1}'; fi
}
normalize_build() { sed '/^AH[0-9][0-9]*:/d; /^[[:space:]]*$/d; s/^[[:space:]]*//; s/[[:space:]]*$//'; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

if [ "$web_server" = nginx ]; then
  if [ -n "$web_server_binary" ]; then web_cmd=$web_server_binary; else web_cmd=$(command -v nginx || true); fi
  [ -n "$web_cmd" ] && [ -x "$web_cmd" ] || { echo "nginx is not installed" >&2; exit 1; }
  web_version=$($web_cmd -v 2>&1 | sed -n 's#.*nginx/##p')
  web_build=$($web_cmd -V 2>&1 | normalize_build | hash_text)
elif [ "$web_server" = apache ]; then
  if [ -n "$web_server_binary" ]; then
    web_cmd=$web_server_binary
  elif command -v apachectl >/dev/null 2>&1; then
    web_cmd=$(command -v apachectl)
  else
    web_cmd=$(command -v httpd || true)
  fi
  [ -n "$web_cmd" ] && [ -x "$web_cmd" ] || { echo "Apache is not installed" >&2; exit 1; }
  web_version=$($web_cmd -v 2>&1 | sed -n 's#.*Apache/\([^ ]*\).*#\1#p' | head -n 1)
  web_build=$($web_cmd -V 2>&1 | normalize_build | hash_text)
else
  echo "unsupported webserver: $web_server" >&2
  exit 1
fi
command -v dpkg-query >/dev/null 2>&1 || { echo "Ubuntu dpkg-query is required" >&2; exit 1; }
if [ "$integration_mode" = distro ]; then
  if [ "$web_server" = apache ]; then web_package=apache2; else web_package=nginx; fi
  dpkg-query -W "$web_package" >/dev/null 2>&1 || { echo "the selected web server must be installed from Ubuntu packages; use --integration external for a pre-installed custom build" >&2; exit 1; }
else
  [ -n "$integration_config" ] || { echo "external integration requires --integration-config" >&2; exit 2; }
  case "$integration_config" in /*) ;; *) echo "--integration-config must be an absolute path" >&2; exit 2 ;; esac
fi

hostname_value=$(hostname 2>/dev/null || printf 'unknown')
payload=$(printf '{"token":"%s","inventory":{"hostname":"%s","os_id":"%s","os_version":"%s","architecture":"%s","web_server":"%s","web_server_version":"%s","web_server_build_hash":"%s","integration_mode":"%s"}}' \
  "$(json_escape "$token")" "$(json_escape "$hostname_value")" "$(json_escape "$os_id")" "$(json_escape "$os_version")" "$architecture" "$web_server" "$(json_escape "$web_version")" "$web_build" "$integration_mode")

resolution=$(curl --fail --silent --show-error --cacert "$ca_file" -H 'Content-Type: application/json' -H 'Accept: text/plain' --data "$payload" "$manager/bootstrap/v1/packages/resolve")
agent_url=$(printf '%s\n' "$resolution" | sed -n '2p')
agent_sha=$(printf '%s\n' "$resolution" | sed -n '3p')
module_url=$(printf '%s\n' "$resolution" | sed -n '4p')
module_sha=$(printf '%s\n' "$resolution" | sed -n '5p')
[ -n "$agent_url" ] && [ -n "$agent_sha" ] && [ -n "$module_url" ] && [ -n "$module_sha" ] || { echo "invalid package resolution" >&2; exit 1; }

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
agent_file="$tmp_dir/mwaf-agent.deb"
module_file="$tmp_dir/mwaf-module.deb"
curl --fail --silent --show-error --cacert "$ca_file" -H "Authorization: Bearer $token" -o "$agent_file" "$agent_url"
curl --fail --silent --show-error --cacert "$ca_file" -H "Authorization: Bearer $token" -o "$module_file" "$module_url"

actual_agent=$(hash_text < "$agent_file")
actual_module=$(hash_text < "$module_file")
[ "$actual_agent" = "$agent_sha" ] || { echo "agent checksum mismatch" >&2; exit 1; }
[ "$actual_module" = "$module_sha" ] || { echo "module checksum mismatch" >&2; exit 1; }

case "$os_id" in
  ubuntu|debian)
    command -v apt-get >/dev/null 2>&1 || { echo "apt-get is required" >&2; exit 1; }
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y "$module_file" "$agent_file"
    ;;
  *) echo "unsupported distribution: $os_id" >&2; exit 1 ;;
esac

if [ "$integration_mode" = external ]; then
  [ -x /usr/lib/mwaf/configure-external ] || { echo "external integration helper is missing from module package" >&2; exit 1; }
  set -- --webserver "$web_server" --binary "$web_cmd" --integration-config "$integration_config" --audit-log "$audit_log" --web-group "$web_group"
  if [ -n "$modsecurity_base" ]; then set -- "$@" --modsecurity-base "$modsecurity_base"; fi
  if [ "$reload_web_server" -eq 1 ]; then set -- "$@" --reload; fi
  /usr/lib/mwaf/configure-external "$@"
fi

install -d -m 0750 /etc/mwaf-agent /var/lib/mwaf-agent /var/lib/mwaf-agent/spool
install -m 0644 "$ca_file" /etc/mwaf-agent/manager-ca.crt
printf '%s\n' "$token" > /etc/mwaf-agent/enrollment.token
chmod 0600 /etc/mwaf-agent/enrollment.token
cat > /etc/mwaf-agent/agent.json <<EOF
{
  "manager_url": "$(json_escape "$manager")",
  "server_name": "$(json_escape "$hostname_value")",
  "web_server": "$(json_escape "$web_server")",
  "web_server_binary": "$(json_escape "$web_cmd")",
  "integration_mode": "$(json_escape "$integration_mode")",
  "enrollment_token_file": "/etc/mwaf-agent/enrollment.token",
  "ca_certificate": "/etc/mwaf-agent/manager-ca.crt",
  "certificate": "/var/lib/mwaf-agent/agent.crt",
  "private_key": "/var/lib/mwaf-agent/agent.key",
  "policy_public_key": "/var/lib/mwaf-agent/policy-signing.pub",
  "policy_path": "/etc/mwaf/active/main.conf",
  "state_directory": "/var/lib/mwaf-agent",
  "spool_directory": "/var/lib/mwaf-agent/spool",
  "audit_log": "$(json_escape "$audit_log")",
  "heartbeat_interval": "30s",
  "certificate_renew_before": "720h",
  "event_flush_interval": "2s",
  "event_retry_max": "1m",
  "event_batch_size": 500,
  "event_batches_per_flush": 20,
  "spool_max_bytes": 536870912
}
EOF
chmod 0640 /etc/mwaf-agent/agent.json
systemctl enable --now mwaf-agent
echo "M-WAF Agent and $web_server $integration_mode integration were installed from Manager bundle"
