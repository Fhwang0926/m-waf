#!/bin/sh
set -eu

: "${WEBSERVER:?WEBSERVER is required}"
: "${VERSION:?VERSION is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"
: "${METADATA_DIR:?METADATA_DIR is required}"
INTEGRATION_MODE=${INTEGRATION_MODE:-distro}
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
case "$INTEGRATION_MODE" in distro|external) ;; *) echo "unsupported integration mode: $INTEGRATION_MODE" >&2; exit 1 ;; esac

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT INT TERM
mkdir -p "$OUTPUT_DIR" "$METADATA_DIR" "$root/DEBIAN" "$root/usr/share/mwaf/integration" "$root/usr/share/doc/mwaf-modsecurity-$WEBSERVER"
case "$WEBSERVER" in apache|nginx) ;; *) echo "unsupported webserver: $WEBSERVER" >&2; exit 1 ;; esac
if [ "$WEBSERVER" = apache ]; then
  RUNTIME_ABI=${RUNTIME_ABI:-modsecurity-v2}
else
  RUNTIME_ABI=${RUNTIME_ABI:-modsecurity-v3}
fi
if [ -z "${MWAF_DEB_TARGETS:-}" ]; then
  if [ "$WEBSERVER" = apache ] && [ "$INTEGRATION_MODE" = distro ]; then
    MWAF_DEB_TARGETS='ubuntu:18.04 ubuntu:20.04 ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 debian:12'
  else
    MWAF_DEB_TARGETS='ubuntu:24.04 ubuntu:26.04 debian:12'
  fi
fi

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
      dependency='apache2, libapache2-mod-security2 (>= 2.9.2), logrotate'
      mkdir -p "$root/etc/apache2/conf-available"
      install -m 0644 packaging/module/deb/mwaf-apache.conf "$root/etc/apache2/conf-available/mwaf.conf"
      postinst_body=':'
      prerm_body='if [ -e /etc/apache2/conf-enabled/mwaf.conf ]; then a2disconf mwaf >/dev/null; if ! apachectl configtest; then a2enconf mwaf >/dev/null; exit 1; fi; if systemctl is-active --quiet apache2; then systemctl reload apache2; fi; fi'
      ;;
    nginx)
      package_name=mwaf-modsecurity-nginx
      dependency='nginx (>= 1.22.0), libnginx-mod-http-modsecurity (>= 1.0.3), logrotate'
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
install -d -m 0750 /etc/mwaf/active
if [ ! -e /etc/mwaf/active/main.conf ]; then
  printf '%s\n' '# M-WAF unassigned safe policy.' 'SecRuleEngine DetectionOnly' > /etc/mwaf/active/main.conf
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
for target in $MWAF_DEB_TARGETS; do
  case "$target" in
    ubuntu:18.04|ubuntu:20.04|ubuntu:22.04)
      if [ "$WEBSERVER" != apache ] || [ "$INTEGRATION_MODE" != distro ]; then
        echo "unsupported DEB target for $WEBSERVER $INTEGRATION_MODE: $target" >&2
        exit 1
      fi
      ;;
    ubuntu:24.04|ubuntu:26.04|debian:12) ;;
    *) echo "unsupported DEB target: $target" >&2; exit 1 ;;
  esac
  target_os=${target%%:*}
  target_version=${target#*:}
  jq -n --arg id "${package_name}-${target_os}-${target_version}-amd64-${VERSION}" --arg name "$package_name" --arg version "$VERSION" --arg os_id "$target_os" --arg os_version "$target_version" --arg web "$WEBSERVER" --arg integration "$INTEGRATION_MODE" --arg runtime_abi "$RUNTIME_ABI" --arg path "$filename" '{id:$id,kind:"module",name:$name,version:$version,os_id:$os_id,os_version:$os_version,architecture:"amd64",web_server:$web,integration_mode:$integration,runtime_abi:$runtime_abi,policy_delivery:"bundle",path:$path}' > "$METADATA_DIR/module-$WEBSERVER-$INTEGRATION_MODE-${target_os}-${target_version}.json"
done
