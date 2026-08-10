#!/bin/sh
set -eu

manager=""
token=""
token_file=""
install_token=""
install_token_file=""
install_token_stdin=0
ca_file=""
server_name=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manager) manager=$2; shift 2 ;;
    --token) token=$2; shift 2 ;;
    --token-file) token_file=$2; shift 2 ;;
    --install-token-file) install_token_file=$2; shift 2 ;;
    --install-token-stdin) install_token_stdin=1; shift ;;
    --ca) ca_file=$2; shift 2 ;;
    --name) server_name=$2; shift 2 ;;
    *) echo "unknown argument: $1; the first-stage installer accepts Agent registration options only" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -n "$manager" ] && [ -r "$ca_file" ] || { echo "--manager and readable --ca are required" >&2; exit 2; }
[ ! -s /var/lib/mwaf-agent/server-id ] || { echo "this server is already enrolled; use the existing M-WAF Agent identity" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo "apt-get is required to install the signed Agent DEB" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd systemctl is required" >&2; exit 1; }
[ -r /etc/os-release ] || { echo "unsupported OS: /etc/os-release missing" >&2; exit 1; }

. /etc/os-release
os_id=${ID:-unknown}
os_version=${VERSION_ID:-unknown}
case "$os_id:$os_version" in
  ubuntu:24.04|debian:12) ;;
  *) echo "unsupported OS: $os_id $os_version; supported: Ubuntu 24.04 LTS or Debian 12" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64) architecture=amd64 ;;
  *) echo "unsupported architecture: $(uname -m); this release supports x86_64 only" >&2; exit 1 ;;
esac

if [ -n "$token_file" ]; then
  if [ -n "$token" ] || [ -n "$install_token_file" ] || [ "$install_token_stdin" -eq 1 ]; then
    echo "use only one token source" >&2
    exit 2
  fi
  [ -r "$token_file" ] || { echo "enrollment token file is not readable" >&2; exit 2; }
  token=$(sed -n '1p' "$token_file")
fi
if [ -n "$token" ] && { [ -n "$install_token_file" ] || [ "$install_token_stdin" -eq 1 ]; }; then
  echo "use either an enrollment token or an enterprise install token source" >&2
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
      IFS= read -r install_token || { echo "could not read enterprise install token" >&2; exit 2; }
      stty echo
      trap - EXIT HUP INT TERM
    else
      IFS= read -r install_token || { echo "could not read enterprise install token" >&2; exit 2; }
    fi
    printf '\n' >&2
  else
    echo "--token, --token-file, --install-token-file or --install-token-stdin is required" >&2
    exit 2
  fi
fi
[ -n "$token$install_token" ] || { echo "installation token is empty" >&2; exit 2; }

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

hostname_value=$(hostname 2>/dev/null || printf 'unknown')
[ -n "$server_name" ] || server_name=$hostname_value
event_verification_token=$token
if [ -z "$token" ]; then
  event_verification_token=$install_token
  session_payload=$(printf '{"name":"%s","inventory":{"hostname":"%s","os_id":"%s","os_version":"%s","architecture":"%s","installation_mode":"discovery","installation_stage":"PLAN_REQUIRED"}}' \
    "$(json_escape "$server_name")" "$(json_escape "$hostname_value")" "$(json_escape "$os_id")" "$(json_escape "$os_version")" "$architecture")
  install_auth_file=$(mktemp)
  chmod 0600 "$install_auth_file"
  trap 'rm -f "$install_auth_file"' EXIT HUP INT TERM
  printf 'Authorization: Bearer %s\n' "$install_token" > "$install_auth_file"
  token=$(curl --fail --silent --show-error --cacert "$ca_file" -H "@$install_auth_file" -H 'Content-Type: application/json' -H 'Accept: text/plain' --data "$session_payload" "$manager/bootstrap/v1/sessions")
  rm -f "$install_auth_file"
  trap - EXIT HUP INT TERM
  [ -n "$token" ] || { echo "Manager did not issue an enrollment session" >&2; exit 1; }
fi

payload=$(printf '{"token":"%s","inventory":{"hostname":"%s","os_id":"%s","os_version":"%s","architecture":"%s","installation_mode":"discovery","installation_stage":"PLAN_REQUIRED"}}' \
  "$(json_escape "$token")" "$(json_escape "$hostname_value")" "$(json_escape "$os_id")" "$(json_escape "$os_version")" "$architecture")
resolution=$(curl --fail --silent --show-error --cacert "$ca_file" -H 'Content-Type: application/json' -H 'Accept: text/plain' --data "$payload" "$manager/bootstrap/v1/packages/resolve")
agent_url=$(printf '%s\n' "$resolution" | sed -n '2p')
agent_sha=$(printf '%s\n' "$resolution" | sed -n '3p')
[ -n "$agent_url" ] && [ -n "$agent_sha" ] || { echo "invalid Agent package resolution" >&2; exit 1; }

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
agent_file="$temporary/mwaf-agent.deb"
curl --fail --silent --show-error --cacert "$ca_file" -H "Authorization: Bearer $token" -o "$agent_file" "$agent_url"
[ "$(hash_file "$agent_file")" = "$agent_sha" ] || { echo "Agent checksum mismatch" >&2; exit 1; }

# mwaf-agent has no runtime package dependencies. This first stage installs no
# Apache, Nginx, ModSecurity Connector, CRS module, or log package.
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=--force-confold install --no-install-recommends -y "$agent_file"

install -d -m 0750 /etc/mwaf-agent /var/lib/mwaf-agent /var/lib/mwaf-agent/spool /etc/mwaf/active
if [ ! -e /etc/mwaf/active/main.conf ]; then
  printf '%s\n' '# M-WAF unassigned safe policy.' 'SecRuleEngine DetectionOnly' > /etc/mwaf/active/main.conf
  chmod 0640 /etc/mwaf/active/main.conf
fi
install -m 0644 "$ca_file" /etc/mwaf-agent/manager-ca.crt
printf '%s\n' "$token" > /etc/mwaf-agent/enrollment.token
printf '%s\n' "$event_verification_token" > /etc/mwaf-agent/event-verification.token
chmod 0600 /etc/mwaf-agent/enrollment.token /etc/mwaf-agent/event-verification.token
cat > /etc/mwaf-agent/agent.json <<EOF
{
  "manager_url": "$(json_escape "$manager")",
  "server_name": "$(json_escape "$server_name")",
  "integration_mode": "distro",
  "installation_mode": "discovery",
  "enrollment_token_file": "/etc/mwaf-agent/enrollment.token",
  "event_verification_token_file": "/etc/mwaf-agent/event-verification.token",
  "ca_certificate": "/etc/mwaf-agent/manager-ca.crt",
  "certificate": "/var/lib/mwaf-agent/agent.crt",
  "private_key": "/var/lib/mwaf-agent/agent.key",
  "policy_public_key": "/var/lib/mwaf-agent/policy-signing.pub",
  "policy_path": "/etc/mwaf/active/main.conf",
  "state_directory": "/var/lib/mwaf-agent",
  "spool_directory": "/var/lib/mwaf-agent/spool",
  "audit_log": "/var/log/modsecurity/audit.jsonl",
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

waited=0
while [ "$waited" -lt 90 ]; do
  if [ -s /var/lib/mwaf-agent/server-id ]; then
    echo "M-WAF Agent registration completed with an unassigned safe policy. Select package-based or custom ZIP installation in Manager; no web-server configuration was changed."
    exit 0
  fi
  systemctl is-active --quiet mwaf-agent || { echo "M-WAF Agent stopped before registration completed" >&2; exit 1; }
  sleep 2
  waited=$((waited + 2))
done
echo "M-WAF Agent is running, but Manager registration was not confirmed within 90 seconds" >&2
exit 1
