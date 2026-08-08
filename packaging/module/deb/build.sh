#!/bin/sh
set -eu

: "${WEBSERVER:?WEBSERVER is required}"
: "${VERSION:?VERSION is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"
: "${METADATA_DIR:?METADATA_DIR is required}"
: "${CRS_ARCHIVE:?CRS_ARCHIVE is required}"
: "${CRS_VERSION:?CRS_VERSION is required}"
INTEGRATION_MODE=${INTEGRATION_MODE:-distro}
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
case "$INTEGRATION_MODE" in distro|external) ;; *) echo "unsupported integration mode: $INTEGRATION_MODE" >&2; exit 1 ;; esac

root=$(mktemp -d)
crs_stage=$(mktemp -d)
trap 'rm -rf "$root" "$crs_stage"' EXIT INT TERM
mkdir -p "$OUTPUT_DIR" "$METADATA_DIR" "$root/DEBIAN" "$root/usr/share/mwaf/policy/default" "$root/usr/share/mwaf/crs" "$root/usr/share/doc/mwaf-modsecurity-$WEBSERVER"
tar -xzf "$CRS_ARCHIVE" -C "$crs_stage" --strip-components=1
cp -R "$crs_stage/rules" "$root/usr/share/mwaf/crs/rules"
install -m 0644 "$crs_stage/crs-setup.conf.example" "$root/usr/share/mwaf/crs/crs-setup.conf"
install -m 0644 "$crs_stage/LICENSE" "$root/usr/share/doc/mwaf-modsecurity-$WEBSERVER/LICENSE.crs"
printf '%s\n' "$CRS_VERSION" > "$root/etc/mwaf/crs.version"
cat > "$root/usr/share/mwaf/policy/default/00-engine.conf" <<'EOF'
# Managed by mwaf-agent. Do not edit.
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
EOF
cat > "$root/usr/share/mwaf/policy/default/20-crs-setup.conf" <<'EOF'
Include /usr/share/mwaf/crs/crs-setup.conf
EOF
cat > "$root/usr/share/mwaf/policy/default/40-crs-rules.conf" <<'EOF'
Include /usr/share/mwaf/crs/rules/*.conf
EOF
case "$WEBSERVER" in apache|nginx) ;; *) echo "unsupported webserver: $WEBSERVER" >&2; exit 1 ;; esac

if [ "$INTEGRATION_MODE" = external ]; then
  package_name="mwaf-modsecurity-$WEBSERVER-external"
  dependency='logrotate'
  mkdir -p "$root/usr/lib/mwaf"
  install -m 0755 packaging/module/external/configure.sh "$root/usr/lib/mwaf/configure-external"
  postinst_body=':'
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
Description: M-WAF $WEBSERVER ModSecurity integration with unchanged OWASP CRS $CRS_VERSION rules
EOF
cat > "$root/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e
active=/etc/mwaf/active
revisions=/etc/mwaf/revisions
if [ ! -L "\$active" ]; then
  install -d -m 0750 "\$revisions"
  legacy="\$revisions/legacy-package"
  if [ -e "\$legacy" ]; then
    legacy="\$revisions/legacy-package-\$(date +%s)"
  fi
  install -d -m 0750 "\$legacy"
  if [ -d "\$active" ]; then
    for policy_file in "\$active"/*.conf; do
      [ -f "\$policy_file" ] || continue
      policy_name=\$(basename "\$policy_file")
      if [ "\$policy_name" = main.conf ]; then policy_name=00-engine.conf; fi
      cp -p "\$policy_file" "\$legacy/\$policy_name"
    done
  fi
  for policy_name in 00-engine.conf 20-crs-setup.conf 40-crs-rules.conf; do
    if [ ! -f "\$legacy/\$policy_name" ]; then
      cp "/usr/share/mwaf/policy/default/\$policy_name" "\$legacy/\$policy_name"
    fi
  done
  if [ ! -f "\$legacy/main.conf" ]; then
    printf '%s\n' '# Compatibility entry for conf-v1 policy rollback. Managed by mwaf-agent.' > "\$legacy/main.conf"
  fi
  if [ -e "\$active" ]; then mv "\$active" "\$active.mwaf-old"; fi
  ln -s "\$legacy" "\$active"
  if [ -d "\$active.mwaf-old" ]; then rm -rf "\$active.mwaf-old"; fi
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

filename="${package_name}_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$root" "$OUTPUT_DIR/$filename"
jq -n --arg id "${package_name}-ubuntu-24.04-amd64-${VERSION}" --arg name "$package_name" --arg version "$VERSION" --arg web "$WEBSERVER" --arg integration "$INTEGRATION_MODE" --arg crs_version "$CRS_VERSION" --arg path "$filename" '{id:$id,kind:"module",name:$name,version:$version,os_id:"ubuntu",os_version:"24.04",architecture:"amd64",web_server:$web,integration_mode:$integration,crs_version:$crs_version,path:$path}' > "$METADATA_DIR/module-$WEBSERVER-$INTEGRATION_MODE.json"
