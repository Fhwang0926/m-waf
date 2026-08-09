#!/bin/sh
set -eu

: "${WEBSERVER:?WEBSERVER is required}"
: "${VERSION:?VERSION is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"
: "${METADATA_DIR:?METADATA_DIR is required}"
INTEGRATION_MODE=${INTEGRATION_MODE:-distro}
RUNTIME_ABI=${RUNTIME_ABI:-modsecurity-v3}
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
case "$INTEGRATION_MODE" in distro|external) ;; *) echo "unsupported integration mode: $INTEGRATION_MODE" >&2; exit 1 ;; esac

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT INT TERM
mkdir -p "$OUTPUT_DIR" "$METADATA_DIR" "$root/DEBIAN" "$root/usr/share/mwaf/integration" "$root/usr/share/doc/mwaf-modsecurity-$WEBSERVER"
case "$WEBSERVER" in apache|nginx) ;; *) echo "unsupported webserver: $WEBSERVER" >&2; exit 1 ;; esac

if [ "$INTEGRATION_MODE" = external ]; then
  package_name="mwaf-modsecurity-$WEBSERVER-external"
  dependency='logrotate'
  mkdir -p "$root/usr/lib/mwaf"
  install -m 0755 packaging/module/external/configure.sh "$root/usr/lib/mwaf/configure-external"
  postinst_body=':'
  prerm_body=':'
else
  mkdir -p "$root/etc/logrotate.d" "$root/var/log/modsecurity"
  cat > "$root/etc/logrotate.d/mwaf-modsecurity" <<'EOF'
/var/log/modsecurity/audit.jsonl {
    daily
    rotate 14
    maxsize 100M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su root www-data
}
EOF
  case "$WEBSERVER" in
    apache)
      package_name=mwaf-modsecurity-apache
      dependency='apache2, libapache2-mod-security2 (>= 2.9.7), logrotate'
      mkdir -p "$root/etc/apache2/conf-available"
      install -m 0644 packaging/module/deb/mwaf-apache.conf "$root/etc/apache2/conf-available/mwaf.conf"
      postinst_body='a2enmod security2 >/dev/null'
      prerm_body='if [ -e /etc/apache2/conf-enabled/mwaf.conf ]; then a2disconf mwaf >/dev/null; if ! apachectl configtest; then a2enconf mwaf >/dev/null; exit 1; fi; if systemctl is-active --quiet apache2; then systemctl reload apache2; fi; fi'
      ;;
    nginx)
      package_name=mwaf-modsecurity-nginx
      dependency='nginx (>= 1.24.0), libnginx-mod-http-modsecurity (>= 1.0.3), logrotate'
      install -m 0644 packaging/module/deb/mwaf-nginx.conf "$root/usr/share/mwaf/integration/nginx.conf"
      install -m 0644 packaging/module/deb/modsecurity-nginx.conf "$root/usr/share/mwaf/integration/modsecurity-nginx.conf"
      postinst_body=':'
      prerm_body='if [ -f /etc/nginx/conf.d/mwaf.conf ]; then install -d -m 0750 /etc/mwaf/disabled; mv /etc/nginx/conf.d/mwaf.conf /etc/mwaf/disabled/nginx.conf; if ! nginx -t; then mv /etc/mwaf/disabled/nginx.conf /etc/nginx/conf.d/mwaf.conf; exit 1; fi; if systemctl is-active --quiet nginx; then systemctl reload nginx; fi; fi'
      ;;
  esac
fi

cat > "$root/DEBIAN/control" <<EOF
Package: $package_name
Version: $VERSION
Section: httpd
Priority: optional
Architecture: amd64
Depends: $dependency
Maintainer: M-WAF Project
Description: M-WAF $WEBSERVER ModSecurity Filter integration; signed rules are delivered separately
EOF
cat > "$root/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e
if [ ! -e /etc/mwaf/active ]; then
  install -d -m 0750 /etc/mwaf/active
  printf '%s\n' '# Policy staging placeholder. Not included by the web server.' > /etc/mwaf/active/main.conf
  chmod 0640 /etc/mwaf/active/main.conf
fi
if [ "$INTEGRATION_MODE" = "distro" ]; then
install -d -o root -g www-data -m 0770 /var/log/modsecurity
touch /var/log/modsecurity/audit.jsonl
chown root:www-data /var/log/modsecurity/audit.jsonl
chmod 0660 /var/log/modsecurity/audit.jsonl
fi
$postinst_body
exit 0
EOF
chmod 0755 "$root/DEBIAN/postinst"

cat > "$root/DEBIAN/prerm" <<EOF
#!/bin/sh
set -e
if [ "\${1:-}" = remove ] || [ "\${1:-}" = deconfigure ]; then
$prerm_body
fi
exit 0
EOF
chmod 0755 "$root/DEBIAN/prerm"

filename="${package_name}_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$root" "$OUTPUT_DIR/$filename"
jq -n --arg id "${package_name}-ubuntu-24.04-amd64-${VERSION}" --arg name "$package_name" --arg version "$VERSION" --arg web "$WEBSERVER" --arg integration "$INTEGRATION_MODE" --arg runtime_abi "$RUNTIME_ABI" --arg path "$filename" '{id:$id,kind:"module",name:$name,version:$version,os_id:"ubuntu",os_version:"24.04",architecture:"amd64",web_server:$web,integration_mode:$integration,runtime_abi:$runtime_abi,policy_delivery:"bundle",path:$path}' > "$METADATA_DIR/module-$WEBSERVER-$INTEGRATION_MODE.json"
