#!/bin/sh
set -eu

manager=""
token=""
install_token=""
event_verification_token=""
install_token_file=""
install_token_stdin=0
ca_file=""
web_server=""
web_server_binary=""
server_name=""
integration_mode="distro"
installation_mode="package"
integration_config=""
audit_log="/var/log/modsecurity/audit.jsonl"
web_group="www-data"
modsecurity_base=""
reload_web_server=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manager) manager=$2; shift 2 ;;
    --token) token=$2; shift 2 ;;
    --install-token-file) install_token_file=$2; shift 2 ;;
    --install-token-stdin) install_token_stdin=1; shift ;;
    --ca) ca_file=$2; shift 2 ;;
    --name) server_name=$2; shift 2 ;;
    --webserver) web_server=$2; shift 2 ;;
    --webserver-bin) web_server_binary=$2; shift 2 ;;
    --integration) integration_mode=$2; shift 2 ;;
    --module-install) installation_mode=$2; shift 2 ;;
    --integration-config) integration_config=$2; shift 2 ;;
    --audit-log) audit_log=$2; shift 2 ;;
    --web-group) web_group=$2; shift 2 ;;
    --modsecurity-base) modsecurity_base=$2; shift 2 ;;
    --reload) reload_web_server=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -n "$manager" ] && [ -r "$ca_file" ] || { echo "--manager and readable --ca are required" >&2; exit 2; }
if [ -n "$token" ] && { [ -n "$install_token_file" ] || [ "$install_token_stdin" -eq 1 ]; }; then
  echo "use either legacy --token or an enterprise install token source" >&2
  exit 2
fi
if [ -z "$token" ]; then
  if [ -n "$install_token_file" ] && [ "$install_token_stdin" -eq 1 ]; then
    echo "use either --install-token-file or --install-token-stdin" >&2
    exit 2
  elif [ -n "$install_token_file" ]; then
    [ -r "$install_token_file" ] || { echo "enterprise install token file is not readable" >&2; exit 2; }
    install_token=$(sed -n '1p' "$install_token_file")
  elif [ "$install_token_stdin" -eq 1 ]; then
    printf 'M-WAF enterprise install token: ' >&2
    if [ -t 0 ]; then
      stty -echo
      trap 'stty echo' EXIT HUP INT TERM
      if ! IFS= read -r install_token; then
        echo "could not read enterprise install token" >&2
        exit 2
      fi
      stty echo
      trap - EXIT HUP INT TERM
    else
      IFS= read -r install_token || { echo "could not read enterprise install token" >&2; exit 2; }
    fi
    printf '\n' >&2
  else
    echo "--token, --install-token-file or --install-token-stdin is required" >&2
    exit 2
  fi
  [ -n "$install_token" ] || { echo "enterprise install token is empty" >&2; exit 2; }
fi
[ ! -s /var/lib/mwaf-agent/server-id ] || { echo "this server is already enrolled; use the existing M-WAF Agent identity" >&2; exit 1; }
if [ -n "$install_token" ]; then event_verification_token=$install_token; else event_verification_token=$token; fi
case "$integration_mode" in distro|external) ;; *) echo "--integration must be distro or external" >&2; exit 2 ;; esac
case "$installation_mode" in package|manual) ;; *) echo "--module-install must be package or manual" >&2; exit 2 ;; esac
if [ "$installation_mode" = manual ] && [ "$integration_mode" != external ]; then
  echo "manual module installation requires --integration external" >&2
  exit 2
fi
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
[ -n "$server_name" ] || server_name=$hostname_value
if [ -z "$token" ]; then
session_payload=$(printf '{"name":"%s","inventory":{"hostname":"%s","os_id":"%s","os_version":"%s","architecture":"%s","web_server":"%s","web_server_version":"%s","web_server_build_hash":"%s","integration_mode":"%s","installation_mode":"%s"}}' \
    "$(json_escape "$server_name")" "$(json_escape "$hostname_value")" "$(json_escape "$os_id")" "$(json_escape "$os_version")" "$architecture" "$web_server" "$(json_escape "$web_version")" "$web_build" "$integration_mode" "$installation_mode")
  install_auth_file=$(mktemp)
  chmod 0600 "$install_auth_file"
  trap 'rm -f "$install_auth_file"' EXIT INT TERM
  printf 'Authorization: Bearer %s\n' "$install_token" > "$install_auth_file"
  token=$(curl --fail --silent --show-error --cacert "$ca_file" -H "@$install_auth_file" -H 'Content-Type: application/json' -H 'Accept: text/plain' --data "$session_payload" "$manager/bootstrap/v1/sessions")
  install_token=""
  rm -f "$install_auth_file"
  [ -n "$token" ] || { echo "Manager did not issue an enrollment session" >&2; exit 1; }
fi
payload=$(printf '{"token":"%s","inventory":{"hostname":"%s","os_id":"%s","os_version":"%s","architecture":"%s","web_server":"%s","web_server_version":"%s","web_server_build_hash":"%s","integration_mode":"%s","installation_mode":"%s"}}' \
  "$(json_escape "$token")" "$(json_escape "$hostname_value")" "$(json_escape "$os_id")" "$(json_escape "$os_version")" "$architecture" "$web_server" "$(json_escape "$web_version")" "$web_build" "$integration_mode" "$installation_mode")

resolution=$(curl --fail --silent --show-error --cacert "$ca_file" -H 'Content-Type: application/json' -H 'Accept: text/plain' --data "$payload" "$manager/bootstrap/v1/packages/resolve")
agent_url=$(printf '%s\n' "$resolution" | sed -n '2p')
agent_sha=$(printf '%s\n' "$resolution" | sed -n '3p')
module_url=$(printf '%s\n' "$resolution" | sed -n '4p')
module_sha=$(printf '%s\n' "$resolution" | sed -n '5p')
[ -n "$agent_url" ] && [ -n "$agent_sha" ] || { echo "invalid Agent package resolution" >&2; exit 1; }
if [ "$installation_mode" = package ]; then
  [ -n "$module_url" ] && [ -n "$module_sha" ] || { echo "invalid module package resolution" >&2; exit 1; }
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
agent_file="$tmp_dir/mwaf-agent.deb"
module_file="$tmp_dir/mwaf-module.deb"
curl --fail --silent --show-error --cacert "$ca_file" -H "Authorization: Bearer $token" -o "$agent_file" "$agent_url"
if [ "$installation_mode" = package ]; then
  curl --fail --silent --show-error --cacert "$ca_file" -H "Authorization: Bearer $token" -o "$module_file" "$module_url"
fi

actual_agent=$(hash_text < "$agent_file")
[ "$actual_agent" = "$agent_sha" ] || { echo "agent checksum mismatch" >&2; exit 1; }
if [ "$installation_mode" = package ]; then
  actual_module=$(hash_text < "$module_file")
  [ "$actual_module" = "$module_sha" ] || { echo "module checksum mismatch" >&2; exit 1; }
fi

case "$os_id" in
  ubuntu|debian)
    command -v apt-get >/dev/null 2>&1 || { echo "apt-get is required" >&2; exit 1; }
    if [ "$installation_mode" = package ]; then
      DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y "$module_file" "$agent_file"
    else
      DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y "$agent_file" logrotate
    fi
    ;;
  *) echo "unsupported distribution: $os_id" >&2; exit 1 ;;
esac

if [ "$installation_mode" = manual ]; then
  if [ "$web_server" = apache ]; then
    "$web_cmd" -M 2>&1 | grep -q security2_module || { echo "Apache security2_module is not loaded" >&2; exit 1; }
  else
    { "$web_cmd" -V; "$web_cmd" -T; } 2>&1 | grep -Eq 'modsecurity|ngx_http_modsecurity_module' || { echo "Nginx ModSecurity connector is not loaded" >&2; exit 1; }
  fi
  install -d -m 0750 /etc/mwaf/active
  if [ ! -f /etc/mwaf/active/main.conf ]; then printf '%s\n' '# Policy staging placeholder. Not included by the web server.' > /etc/mwaf/active/main.conf; fi
  chmod 0640 /etc/mwaf/active/main.conf
  install -d -o root -g "$web_group" -m 0770 "$(dirname "$audit_log")"
  touch "$audit_log"
  chown root:"$web_group" "$audit_log"
  chmod 0660 "$audit_log"
  cat > /etc/logrotate.d/mwaf-modsecurity-manual <<EOF
$audit_log {
    daily
    rotate 14
    maxsize 100M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su root $web_group
}
EOF
  install -d -m 0750 /var/lib/mwaf-agent
  printf '%s\n' "manual:$web_server:$web_version:$web_build" > /var/lib/mwaf-agent/connector.version
  chmod 0640 /var/lib/mwaf-agent/connector.version
fi

install -d -m 0750 /etc/mwaf-agent /var/lib/mwaf-agent /var/lib/mwaf-agent/spool
install -m 0644 "$ca_file" /etc/mwaf-agent/manager-ca.crt
printf '%s\n' "$token" > /etc/mwaf-agent/enrollment.token
chmod 0600 /etc/mwaf-agent/enrollment.token
printf '%s\n' "$event_verification_token" > /etc/mwaf-agent/event-verification.token
chmod 0600 /etc/mwaf-agent/event-verification.token
event_verification_token=""
cat > /etc/mwaf-agent/agent.json <<EOF
{
  "manager_url": "$(json_escape "$manager")",
  "server_name": "$(json_escape "$server_name")",
  "web_server": "$(json_escape "$web_server")",
  "web_server_binary": "$(json_escape "$web_cmd")",
  "integration_mode": "$(json_escape "$integration_mode")",
  "installation_mode": "$(json_escape "$installation_mode")",
  "enrollment_token_file": "/etc/mwaf-agent/enrollment.token",
  "event_verification_token_file": "/etc/mwaf-agent/event-verification.token",
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

policy_ready=0
policy_wait=0
while [ "$policy_wait" -lt 90 ]; do
  if [ -L /etc/mwaf/active ] && [ -s /var/lib/mwaf-agent/desired-state.json ]; then policy_ready=1; break; fi
  systemctl is-active --quiet mwaf-agent || { echo "M-WAF Agent stopped before the initial policy was applied" >&2; exit 1; }
  sleep 2
  policy_wait=$((policy_wait + 2))
done
if [ "$policy_ready" -ne 1 ]; then
  systemctl disable --now mwaf-agent >/dev/null 2>&1 || true
  echo "initial signed LTS policy was not applied; web-server integration remains disabled" >&2
  exit 1
fi

if [ "$integration_mode" = external ]; then
  [ -x /usr/lib/mwaf/configure-external ] || { echo "external integration helper is missing" >&2; exit 1; }
  set -- --webserver "$web_server" --binary "$web_cmd" --integration-config "$integration_config" --audit-log "$audit_log" --web-group "$web_group" --reload
  if [ -n "$modsecurity_base" ]; then set -- "$@" --modsecurity-base "$modsecurity_base"; fi
  /usr/lib/mwaf/configure-external "$@"
elif [ "$web_server" = apache ]; then
  a2enconf mwaf >/dev/null
  if ! apachectl configtest; then a2disconf mwaf >/dev/null; echo "Apache configtest failed; M-WAF include was disabled" >&2; exit 1; fi
  if systemctl is-active --quiet apache2; then systemctl reload apache2; fi
  integration_config=/etc/apache2/conf-available/mwaf.conf
else
  [ -r /usr/share/mwaf/integration/nginx.conf ] && [ -r /usr/share/mwaf/integration/modsecurity-nginx.conf ] || { echo "Nginx integration files are missing" >&2; exit 1; }
  if [ -e /etc/nginx/conf.d/mwaf.conf ] && ! cmp -s /etc/nginx/conf.d/mwaf.conf /usr/share/mwaf/integration/nginx.conf; then echo "refusing to replace unmanaged /etc/nginx/conf.d/mwaf.conf" >&2; exit 1; fi
  install -d -m 0750 /etc/mwaf/nginx
  install -m 0644 /usr/share/mwaf/integration/modsecurity-nginx.conf /etc/mwaf/nginx/modsecurity.conf
  install -m 0644 /usr/share/mwaf/integration/nginx.conf /etc/nginx/conf.d/mwaf.conf
  if ! nginx -t; then rm -f /etc/nginx/conf.d/mwaf.conf; echo "Nginx configtest failed; M-WAF include was removed" >&2; exit 1; fi
  if systemctl is-active --quiet nginx; then systemctl reload nginx; fi
  integration_config=/etc/nginx/conf.d/mwaf.conf
fi

install -d -m 0750 /var/lib/mwaf
integration_sha=""
if [ -r "$integration_config" ]; then integration_sha=$(hash_text < "$integration_config"); fi
integration_package=""
if [ "$installation_mode" = package ]; then integration_package="mwaf-modsecurity-$web_server"; fi
if [ "$installation_mode:$integration_mode" = package:external ]; then integration_package="$integration_package-external"; fi
cat > /var/lib/mwaf/install-state.json <<EOF
{
  "schema_version": 1,
  "web_server": "$(json_escape "$web_server")",
  "integration_mode": "$(json_escape "$integration_mode")",
  "installation_mode": "$(json_escape "$installation_mode")",
  "integration_config": "$(json_escape "$integration_config")",
  "integration_sha256": "$integration_sha",
  "agent_package": "mwaf-agent",
  "integration_package": "$(json_escape "$integration_package")",
  "managed_files": [{"path":"$(json_escape "$integration_config")","sha256":"$integration_sha"},{"path":"/etc/mwaf/active","sha256":"signed-policy-symlink"}],
  "active_policy": "/etc/mwaf/active",
  "backup_directory": "/etc/mwaf/disabled"
}
EOF
chmod 0600 /var/lib/mwaf/install-state.json
desired_revision=$(sed -n 's/.*"revision_id": "\([^"]*\)".*/\1/p' /var/lib/mwaf-agent/desired-state.json | head -n 1)
heartbeat_confirmed=0
heartbeat_wait=0
while [ "$heartbeat_wait" -lt 90 ]; do
  if [ -n "$desired_revision" ] && [ -r /var/lib/mwaf-agent/last-heartbeat-policy ] && [ "$(sed -n '1p' /var/lib/mwaf-agent/last-heartbeat-policy)" = "$desired_revision" ]; then heartbeat_confirmed=1; break; fi
  systemctl is-active --quiet mwaf-agent || break
  sleep 2
  heartbeat_wait=$((heartbeat_wait + 2))
done
if [ "$heartbeat_confirmed" -ne 1 ]; then
  /usr/sbin/mwaf-uninstall --package-prerm >/dev/null 2>&1 || true
  echo "Manager가 적용 개정본 heartbeat를 확인하지 못해 웹서버 연동을 비활성화했습니다." >&2
  exit 1
fi
echo "M-WAF Agent and $web_server $integration_mode/$installation_mode integration were installed after the signed LTS policy was applied"
