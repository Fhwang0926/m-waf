#!/bin/sh
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
runtime_root=${MWAF_DEV_RUNTIME_DIR:-$repository_root/.local/mwaf-manager}
secrets_dir="$script_dir/secrets"
builder_image=${MWAF_DEV_PACKAGE_BUILDER_IMAGE:-mwaf-local-package-builder:ubuntu-24.04}

for required in docker go git jq openssl
do
  command -v "$required" >/dev/null 2>&1 || { echo "$required is required" >&2; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "Docker daemon is not available" >&2; exit 1; }

"$script_dir/prepare.sh" >/dev/null
mkdir -p "$runtime_root/dev-bundles"

base_bundle=${MWAF_DEV_BASE_BUNDLE:-}
base_public_key=${MWAF_DEV_BASE_BUNDLE_PUBLIC_KEY:-}
if [ -n "$base_bundle" ] && [ -z "$base_public_key" ]; then
  base_public_key=${base_bundle%/bundle}/package-signing.pub
fi
if [ -z "$base_bundle" ]; then
  for manifest in $(ls -t "$runtime_root"/bundle-cache/*/bundle/bundle-manifest.json 2>/dev/null || true)
  do
    candidate_bundle=${manifest%/bundle-manifest.json}
    candidate_key=${candidate_bundle%/bundle}/package-signing.pub
    if [ -f "$candidate_key" ] && [ "$(jq -r '.schema_version' "$manifest")" = 2 ] && [ "$(jq -r '.policy_sources | length' "$manifest")" -gt 0 ]; then
      base_bundle=$candidate_bundle
      base_public_key=$candidate_key
      break
    fi
  done
fi
[ -n "$base_bundle" ] && [ -n "$base_public_key" ] || {
  echo "A verified schema-v2 release bundle is required. Run 'make dev' once while GHCR is reachable, then retry." >&2
  exit 1
}

cd "$repository_root"
go run ./cmd/mwaf-bundle -verify-bundle "$base_bundle" -verify-public-key "$base_public_key"

commit=$(git rev-parse HEAD)
short_commit=$(printf '%s' "$commit" | cut -c1-12)
build_stamp=$(date -u +%Y%m%d%H%M%S)
package_version=${MWAF_DEV_PACKAGE_VERSION:-0.1.0~dev.${build_stamp}.${short_commit}}
case "$package_version" in
  ''|*[!0-9A-Za-z.+~:-]*) echo "MWAF_DEV_PACKAGE_VERSION contains unsupported characters" >&2; exit 1 ;;
esac

staging=$(mktemp -d "$runtime_root/dev-bundles/.build.XXXXXX")
published=0
cleanup() {
  if [ "$published" -eq 0 ] && [ -d "$staging" ]; then
    rm -rf "$staging"
  fi
}
trap cleanup EXIT INT TERM
mkdir -p "$staging/packages" "$staging/metadata" "$staging/policy-sources" "$staging/policy-source-metadata"

echo "Building Linux amd64 Agent $package_version"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X github.com/Fhwang0926/m-waf/internal/version.Version=$package_version -X github.com/Fhwang0926/m-waf/internal/version.Commit=$commit" \
  -o "$staging/mwaf-agent" ./cmd/mwaf-agent

docker build --platform linux/amd64 -t "$builder_image" -f build/containers/local-package-builder/Dockerfile build/containers/local-package-builder
docker run --rm --platform linux/amd64 \
  -e VERSION="$package_version" -e COMMIT="$commit" -e MWAF_DEB_TARGETS="ubuntu:24.04 debian:12" \
  -v "$repository_root:/src:ro" -v "$staging:/work" -w /src "$builder_image" sh -eu -c '
    AGENT_BINARY=/work/mwaf-agent OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/agent/deb/build.sh
    WEBSERVER=apache OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
    WEBSERVER=nginx OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
    WEBSERVER=apache INTEGRATION_MODE=external OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
    WEBSERVER=nginx INTEGRATION_MODE=external OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
  '

jq -c '.policy_sources[]' "$base_bundle/bundle-manifest.json" | while IFS= read -r source
do
  source_id=$(printf '%s' "$source" | jq -r '.id')
  index_path=$(printf '%s' "$source" | jq -r '.index_path')
  archive_path=$(printf '%s' "$source" | jq -r '.archive_path // ""')
  index_name=${index_path##*/}
  archive_name=${archive_path##*/}
  cp "$base_bundle/$index_path" "$staging/policy-sources/$index_name"
  if [ -n "$archive_path" ]; then
    cp "$base_bundle/$archive_path" "$staging/policy-sources/$archive_name"
  fi
  printf '%s' "$source" | jq --arg index "$index_name" --arg archive "$archive_name" \
    '.index_path=$index | .archive_path=(if $archive == "" then "" else $archive end) | .compatible_package_ids=[]' \
    > "$staging/policy-source-metadata/$source_id.json"
done

signing_key="$secrets_dir/mwaf_dev_bundle_signing_key.pem"
if [ ! -f "$signing_key" ]; then
  openssl genpkey -algorithm ED25519 -out "$signing_key"
fi
chmod 0600 "$signing_key"

go run ./cmd/mwaf-bundle \
  -metadata "$staging/metadata" -packages "$staging/packages" \
  -policy-source-metadata "$staging/policy-source-metadata" -policy-sources "$staging/policy-sources" \
  -output "$staging/bundle" -key "$signing_key" -public-key-output "$staging/package-signing.pub" \
  -version "dev-$build_stamp-$short_commit" -commit "$commit"
go run ./cmd/mwaf-bundle -verify-bundle "$staging/bundle" -verify-public-key "$staging/package-signing.pub"

final="$runtime_root/dev-bundles/dev-$build_stamp-$short_commit"
mv "$staging" "$final"
published=1
printf '%s\n' "$final" > "$runtime_root/dev-bundle-current"
echo "Local signed development bundle: $final"
echo "Start it with: make dev-full"
