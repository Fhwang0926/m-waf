#!/bin/sh
set -eu

: "${WEBSERVER:?WEBSERVER is required}"
: "${VERSION:?VERSION is required}"
: "${WEB_VERSION:?WEB_VERSION is required}"
: "${WEB_BUILD_HASH:?WEB_BUILD_HASH is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"
: "${METADATA_DIR:?METADATA_DIR is required}"
: "${CRS_ARCHIVE:?CRS_ARCHIVE is required}"
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

root=$(mktemp -d)
crs_stage=$(mktemp -d)
trap 'rm -rf "$root" "$crs_stage"' EXIT INT TERM
mkdir -p "$OUTPUT_DIR" "$METADATA_DIR" "$root/DEBIAN" "$root/etc/logrotate.d" "$root/etc/mwaf/active" "$root/usr/share/mwaf/crs" "$root/usr/share/doc/mwaf-modsecurity-$WEBSERVER" "$root/var/log/modsecurity"
tar -xzf "$CRS_ARCHIVE" -C "$crs_stage" --strip-components=1
cp -R "$crs_stage/rules" "$root/usr/share/mwaf/crs/rules"
install -m 0644 "$crs_stage/crs-setup.conf.example" "$root/usr/share/mwaf/crs/crs-setup.conf"
install -m 0644 "$crs_stage/LICENSE" "$root/usr/share/doc/mwaf-modsecurity-$WEBSERVER/LICENSE.crs"
printf '%s\n' '4.28.0' > "$root/etc/mwaf/crs.version"
cat > "$root/etc/mwaf/active/main.conf" <<'EOF'
# Managed by mwaf-agent. Do not edit.
SecRuleEngine DetectionOnly
EOF
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
    postinst_body='a2enmod security2 >/dev/null; a2enconf mwaf >/dev/null; apachectl configtest; if systemctl is-active --quiet apache2; then systemctl reload apache2; fi'
    ;;
  nginx)
    package_name=mwaf-modsecurity-nginx
    dependency='nginx (>= 1.24.0), libnginx-mod-http-modsecurity (>= 1.0.3), logrotate'
    mkdir -p "$root/etc/nginx/conf.d" "$root/etc/mwaf/nginx"
    install -m 0644 packaging/module/deb/mwaf-nginx.conf "$root/etc/nginx/conf.d/mwaf.conf"
    install -m 0644 packaging/module/deb/modsecurity-nginx.conf "$root/etc/mwaf/nginx/modsecurity.conf"
    postinst_body='nginx -t; if systemctl is-active --quiet nginx; then systemctl reload nginx; fi'
    ;;
  *) echo "unsupported webserver: $WEBSERVER" >&2; exit 1 ;;
esac

cat > "$root/DEBIAN/control" <<EOF
Package: $package_name
Version: $VERSION
Section: httpd
Priority: optional
Architecture: amd64
Depends: $dependency
Maintainer: M-WAF Project
Description: M-WAF $WEBSERVER ModSecurity integration with unchanged OWASP CRS 4.28.0 rules
EOF
cat > "$root/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e
install -d -o root -g www-data -m 0770 /var/log/modsecurity
touch /var/log/modsecurity/audit.jsonl
chown root:www-data /var/log/modsecurity/audit.jsonl
chmod 0660 /var/log/modsecurity/audit.jsonl
$postinst_body
exit 0
EOF
chmod 0755 "$root/DEBIAN/postinst"

filename="${package_name}_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$root" "$OUTPUT_DIR/$filename"
short_hash=$(printf '%s' "$WEB_BUILD_HASH" | cut -c1-16)
jq -n --arg id "${package_name}-ubuntu-24.04-amd64-${WEB_VERSION}-${short_hash}-${VERSION}" --arg name "$package_name" --arg version "$VERSION" --arg web "$WEBSERVER" --arg web_version "$WEB_VERSION" --arg web_hash "$WEB_BUILD_HASH" --arg path "$filename" '{id:$id,kind:"module",name:$name,version:$version,os_id:"ubuntu",os_version:"24.04",architecture:"amd64",web_server:$web,web_server_version:$web_version,web_server_build_hash:$web_hash,path:$path}' > "$METADATA_DIR/module-$WEBSERVER.json"
