#!/bin/sh
set -eu

web_server=""
binary=""
integration_config=""
audit_log="/var/log/modsecurity/audit.jsonl"
web_group="www-data"
base_config=""
reload=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --webserver) web_server=$2; shift 2 ;;
    --binary) binary=$2; shift 2 ;;
    --integration-config) integration_config=$2; shift 2 ;;
    --audit-log) audit_log=$2; shift 2 ;;
    --web-group) web_group=$2; shift 2 ;;
    --modsecurity-base) base_config=$2; shift 2 ;;
    --reload) reload=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
case "$web_server" in apache|nginx) ;; *) echo "--webserver must be apache or nginx" >&2; exit 2 ;; esac
case "$binary" in /*) ;; *) echo "--binary must be an absolute path" >&2; exit 2 ;; esac
case "$integration_config" in /*) ;; *) echo "--integration-config must be an absolute path" >&2; exit 2 ;; esac
case "$audit_log" in /*) ;; *) echo "--audit-log must be an absolute path" >&2; exit 2 ;; esac
[ -x "$binary" ] || { echo "web-server control binary is not executable: $binary" >&2; exit 1; }
[ -d "$(dirname "$integration_config")" ] || { echo "integration config parent directory does not exist" >&2; exit 1; }
getent group "$web_group" >/dev/null 2>&1 || { echo "web-server group does not exist: $web_group" >&2; exit 1; }
if [ -n "$base_config" ]; then
  case "$base_config" in /*) ;; *) echo "--modsecurity-base must be an absolute path" >&2; exit 2 ;; esac
  [ -r "$base_config" ] || { echo "ModSecurity base config is not readable: $base_config" >&2; exit 1; }
fi

marker="# Managed by M-WAF external integration."
if [ -e "$integration_config" ] && ! grep -Fqx "$marker" "$integration_config"; then
  echo "refusing to overwrite unmanaged integration config: $integration_config" >&2
  exit 1
fi

case "$web_server" in
  apache)
    "$binary" -M 2>&1 | grep -q 'security2_module' || { echo "Apache security2_module is not loaded" >&2; exit 1; }
    ;;
  nginx)
    nginx_details=$("$binary" -V 2>&1 || true)
    nginx_config=$("$binary" -T 2>&1) || { printf '%s\n' "$nginx_config" >&2; exit 1; }
    printf '%s\n%s\n' "$nginx_details" "$nginx_config" | grep -Eq 'ngx_http_modsecurity_module|ModSecurity-nginx|modsecurity[[:space:]]+on;' || {
      echo "Nginx ModSecurity connector is not visible in build or active configuration" >&2
      exit 1
    }
    ;;
esac

engine_dir=/etc/mwaf/external
engine_config="$engine_dir/$web_server.conf"
logrotate_config=/etc/logrotate.d/mwaf-modsecurity
[ "$integration_config" != "$engine_config" ] || { echo "integration config and generated engine config must be different files" >&2; exit 2; }
[ -z "$base_config" ] || [ "$base_config" != "$engine_config" ] || { echo "ModSecurity base config cannot be the generated engine config" >&2; exit 2; }
temporary=$(mktemp -d)
success=0

backup_file() {
  source_path=$1
  backup_path=$2
  if [ -e "$source_path" ]; then
    cp -p "$source_path" "$backup_path"
    printf '1'
  else
    printf '0'
  fi
}

integration_existed=$(backup_file "$integration_config" "$temporary/integration")
engine_existed=$(backup_file "$engine_config" "$temporary/engine")
logrotate_existed=$(backup_file "$logrotate_config" "$temporary/logrotate")

restore_file() {
  existed=$1
  backup_path=$2
  destination=$3
  if [ "$existed" -eq 1 ]; then
    cp -p "$backup_path" "$destination"
  else
    rm -f "$destination"
  fi
}

cleanup() {
  if [ "$success" -ne 1 ]; then
    restore_file "$integration_existed" "$temporary/integration" "$integration_config"
    restore_file "$engine_existed" "$temporary/engine" "$engine_config"
    restore_file "$logrotate_existed" "$temporary/logrotate" "$logrotate_config"
  fi
  rm -rf "$temporary"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -m 0755 "$engine_dir"
install -d -o root -g "$web_group" -m 0770 "$(dirname "$audit_log")"
touch "$audit_log"
chown root:"$web_group" "$audit_log"
chmod 0660 "$audit_log"

{
  printf '%s\n' "$marker"
  if [ -n "$base_config" ]; then
    printf 'Include %s\n' "$base_config"
  fi
  cat <<EOF
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog $audit_log
SecAuditLogFormat JSON
Include /etc/mwaf/active/*.conf
EOF
} > "$temporary/engine.new"
install -m 0644 "$temporary/engine.new" "$engine_config"

case "$web_server" in
  apache)
    {
      printf '%s\n' "$marker"
      printf 'Include %s\n' "$engine_config"
    } > "$temporary/integration.new"
    ;;
  nginx)
    {
      printf '%s\n' "$marker"
      printf 'modsecurity on;\n'
      printf 'modsecurity_rules_file %s;\n' "$engine_config"
    } > "$temporary/integration.new"
    ;;
esac
install -m 0644 "$temporary/integration.new" "$integration_config"

cat > "$temporary/logrotate.new" <<EOF
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
install -m 0644 "$temporary/logrotate.new" "$logrotate_config"

case "$web_server" in
  apache)
    "$binary" configtest
    "$binary" -t -D DUMP_INCLUDES 2>&1 | grep -F "$integration_config" >/dev/null || {
      echo "Apache does not include the dedicated M-WAF config" >&2
      exit 1
    }
    [ "$reload" -eq 0 ] || "$binary" graceful
    ;;
  nginx)
    "$binary" -t
    "$binary" -T 2>&1 | grep -F "configuration file $integration_config:" >/dev/null || {
      echo "Nginx does not include the dedicated M-WAF config" >&2
      exit 1
    }
    [ "$reload" -eq 0 ] || "$binary" -s reload
    ;;
esac

success=1
echo "Configured M-WAF for pre-installed $web_server ModSecurity without replacing the web server or connector."
