#!/bin/sh
set -eu

web_server=${1:-}
dist_dir=${2:-/dist}
case "$web_server" in
  apache) module_package=mwaf-modsecurity-apache ;;
  nginx) module_package=mwaf-modsecurity-nginx ;;
  *) echo "usage: $0 apache|nginx [dist-dir]" >&2; exit 2 ;;
esac

set -- "$dist_dir"/packages/mwaf-agent_*.deb "$dist_dir"/packages/${module_package}_*.deb
[ "$#" -eq 2 ] && [ -f "$1" ] && [ -f "$2" ] || { echo "exactly one Agent and $web_server integration package are required" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
dpkg --unpack "$1" "$2"
apt-get --no-download --fix-broken install --no-install-recommends -y
dpkg-query -W mwaf-agent "$module_package"
/usr/bin/mwaf-agent -version
grep -q "copytruncate" /etc/logrotate.d/mwaf-modsecurity
test ! -e /usr/share/mwaf/crs
test -f /etc/mwaf/active/main.conf
test "$(stat -c '%a:%U:%G' /var/log/modsecurity/audit.jsonl)" = "660:root:www-data"

printf 'M-WAF CI DETECT TARGET\n' > /var/www/html/mwaf-ci-detect
printf 'M-WAF CI BLOCK TARGET\n' > /var/www/html/mwaf-ci-block

write_policy() {
  mode=$1
  target=$2
  marker=$3
  cat > /etc/mwaf/active/main.conf <<EOF
SecRuleEngine $mode
SecAuditEngine On
SecRule REQUEST_URI "@streq $target" "id:1000001,phase:1,deny,status:403,log,auditlog,msg:'$marker'"
EOF
}

wait_for_audit() {
  marker=$1
  attempts=0
  while [ "$attempts" -lt 20 ]; do
    if grep -Fq "$marker" /var/log/modsecurity/audit.jsonl; then return 0; fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "audit log did not contain marker: $marker" >&2
  return 1
}

wait_for_status() {
  target=$1
  expected=$2
  attempts=0
  while [ "$attempts" -lt 20 ]; do
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1$target" || true)
    if [ "$status" = "$expected" ]; then return 0; fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "$target returned ${status:-no response}; expected $expected" >&2
  return 1
}

case "$web_server" in
  apache)
    test ! -e /etc/apache2/conf-enabled/mwaf.conf
    a2enconf mwaf >/dev/null
    configtest() { apachectl configtest; }
    start_server() { apachectl start; }
    reload_server() { apachectl graceful; }
    stop_server() { apachectl stop; }
    apachectl -M 2>&1 | grep -q security2_module
    ;;
  nginx)
    test ! -e /etc/nginx/conf.d/mwaf.conf
    install -d -m 0750 /etc/mwaf/nginx
    install -m 0644 /usr/share/mwaf/integration/modsecurity-nginx.conf /etc/mwaf/nginx/modsecurity.conf
    install -m 0644 /usr/share/mwaf/integration/nginx.conf /etc/nginx/conf.d/mwaf.conf
    configtest() { nginx -t; }
    start_server() { nginx; }
    reload_server() { nginx -s reload; }
    stop_server() { nginx -s quit; }
    ;;
esac

write_policy DetectionOnly /mwaf-ci-detect MWAF_CI_DETECT
configtest
start_server
wait_for_status /mwaf-ci-detect 200
wait_for_audit MWAF_CI_DETECT

write_policy On /mwaf-ci-block MWAF_CI_BLOCK
configtest
reload_server
wait_for_status /mwaf-ci-block 403
wait_for_audit MWAF_CI_BLOCK
stop_server
