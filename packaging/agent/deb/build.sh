#!/bin/sh
set -eu

: "${VERSION:?VERSION is required}"
: "${COMMIT:?COMMIT is required}"
: "${AGENT_BINARY:?AGENT_BINARY is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"
: "${METADATA_DIR:?METADATA_DIR is required}"
MWAF_DEB_TARGETS=${MWAF_DEB_TARGETS:-ubuntu:24.04 debian:12}
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT INT TERM
mkdir -p "$OUTPUT_DIR" "$METADATA_DIR" "$root/DEBIAN" "$root/usr/bin" "$root/usr/sbin" "$root/usr/lib/mwaf" "$root/lib/systemd/system" "$root/usr/share/doc/mwaf-agent"
install -m 0755 "$AGENT_BINARY" "$root/usr/bin/mwaf-agent"
install -m 0755 packaging/agent/mwaf-uninstall "$root/usr/sbin/mwaf-uninstall"
install -m 0755 packaging/module/external/configure.sh "$root/usr/lib/mwaf/configure-external"
install -m 0644 packaging/agent/systemd/mwaf-agent.service "$root/lib/systemd/system/mwaf-agent.service"
printf '%s\n' "source: https://github.com/Fhwang0926/m-waf" "commit: $COMMIT" > "$root/usr/share/doc/mwaf-agent/build-info"
cat > "$root/DEBIAN/control" <<EOF
Package: mwaf-agent
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: M-WAF Project
Description: M-WAF policy management and ModSecurity audit forwarding agent
EOF
cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
exit 0
EOF
chmod 0755 "$root/DEBIAN/postinst"
cat > "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "${1:-}" = remove ] && [ -x /usr/sbin/mwaf-uninstall ]; then
  /usr/sbin/mwaf-uninstall --package-prerm
fi
exit 0
EOF
chmod 0755 "$root/DEBIAN/prerm"

filename="mwaf-agent_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$root" "$OUTPUT_DIR/$filename"
for target in $MWAF_DEB_TARGETS; do
  case "$target" in
    ubuntu:24.04|debian:12) ;;
    *) echo "unsupported DEB target: $target" >&2; exit 1 ;;
  esac
  target_os=${target%%:*}
  target_version=${target#*:}
  jq -n --arg id "mwaf-agent-${target_os}-${target_version}-amd64-${VERSION}" --arg version "$VERSION" --arg os_id "$target_os" --arg os_version "$target_version" --arg path "$filename" '{id:$id,kind:"agent",name:"mwaf-agent",version:$version,os_id:$os_id,os_version:$os_version,architecture:"amd64",path:$path}' > "$METADATA_DIR/agent-${target_os}-${target_version}.json"
done
