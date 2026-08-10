#!/bin/sh
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
runtime_root=${MWAF_DEV_RUNTIME_DIR:-$repository_root/.local/mwaf-manager}
secrets_dir="$script_dir/secrets"
builder_image=${MWAF_DEV_PACKAGE_BUILDER_IMAGE:-mwaf-local-package-builder:ubuntu-24.04}
agent_only=${MWAF_DEV_AGENT_ONLY:-false}
case "$agent_only" in true|false) ;; *) echo "MWAF_DEV_AGENT_ONLY must be true or false" >&2; exit 1 ;; esac

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
  active_release="$runtime_root/dev-bundle-active"
  if [ -f "$active_release/bundle/bundle-manifest.json" ] && [ -f "$active_release/package-signing.pub" ]; then
    base_bundle="$active_release/bundle"
    base_public_key="$active_release/package-signing.pub"
  fi
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
agent_base_version=$(sed -n '1p' packaging/agent/VERSION)
sh scripts/check-agent-version.sh >/dev/null
agent_version=${MWAF_DEV_AGENT_VERSION:-${agent_base_version}~dev.${build_stamp}.${short_commit}}
module_version=${MWAF_DEV_PACKAGE_VERSION:-0.1.0~dev.${build_stamp}.${short_commit}}
case "$agent_version$module_version" in
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

echo "Building Linux amd64 Agent $agent_version"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X github.com/Fhwang0926/m-waf/internal/version.Version=$agent_version -X github.com/Fhwang0926/m-waf/internal/version.Commit=$commit" \
  -o "$staging/mwaf-agent" ./cmd/mwaf-agent

docker build --platform linux/amd64 -t "$builder_image" -f build/containers/local-package-builder/Dockerfile build/containers/local-package-builder
docker run --rm --platform linux/amd64 \
  -e AGENT_VERSION="$agent_version" -e MODULE_VERSION="$module_version" -e COMMIT="$commit" -e AGENT_ONLY="$agent_only" \
  -e MWAF_AGENT_DEB_TARGETS="ubuntu:18.04 ubuntu:24.04 debian:12" \
  -e MWAF_DEB_TARGETS="ubuntu:24.04 debian:12" \
  -v "$repository_root:/src:ro" -v "$staging:/work" -w /src "$builder_image" sh -eu -c '
    VERSION="$AGENT_VERSION" AGENT_BINARY=/work/mwaf-agent OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/agent/deb/build.sh
    if [ "$AGENT_ONLY" = false ]; then
      WEBSERVER=apache VERSION="$MODULE_VERSION" OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
      WEBSERVER=nginx VERSION="$MODULE_VERSION" OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
      WEBSERVER=apache INTEGRATION_MODE=external VERSION="$MODULE_VERSION" OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
      WEBSERVER=nginx INTEGRATION_MODE=external VERSION="$MODULE_VERSION" OUTPUT_DIR=/work/packages METADATA_DIR=/work/metadata packaging/module/deb/build.sh
    fi
  '

if [ "$agent_only" = true ]; then
  artifact_index=0
  jq -c '.artifacts[]' "$base_bundle/bundle-manifest.json" | while IFS= read -r artifact
  do
    artifact_index=$((artifact_index + 1))
    artifact_id=$(printf '%s' "$artifact" | jq -r '.id')
    artifact_kind=$(printf '%s' "$artifact" | jq -r '.kind')
    artifact_path=$(printf '%s' "$artifact" | jq -r '.path')
    artifact_name=${artifact_path##*/}
    is_rollback=$(jq -r --arg id "$artifact_id" 'any(.artifacts[]; .rollback_id == $id)' "$base_bundle/bundle-manifest.json")
    if [ "$artifact_kind" = module ]; then
      cp "$base_bundle/$artifact_path" "$staging/packages/$artifact_name"
      printf '%s' "$artifact" | jq --arg path "$artifact_name" '.path=$path' > "$staging/metadata/base-module-$artifact_index.json"
    elif [ "$artifact_kind" = agent ] && [ "$is_rollback" = false ]; then
      cp "$base_bundle/$artifact_path" "$staging/packages/$artifact_name"
      printf '%s' "$artifact" | jq --arg path "$artifact_name" '.path=$path | .rollback_id=""' > "$staging/metadata/rollback-agent-$artifact_index.json"
      target_os=$(printf '%s' "$artifact" | jq -r '.os_id')
      target_version=$(printf '%s' "$artifact" | jq -r '.os_version')
      current_metadata="$staging/metadata/agent-$target_os-$target_version.json"
      [ -f "$current_metadata" ] || { echo "new Agent metadata is missing for $target_os $target_version" >&2; exit 1; }
      jq --arg rollback "$artifact_id" '.rollback_id=$rollback' "$current_metadata" > "$current_metadata.next"
      mv "$current_metadata.next" "$current_metadata"
    fi
  done
fi

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

if [ "$agent_only" = true ]; then
  go run ./cmd/mwaf-bundle \
    -metadata "$staging/metadata" -packages "$staging/packages" \
    -policy-source-metadata "$staging/policy-source-metadata" -policy-sources "$staging/policy-sources" \
    -output "$staging/bundle" -key "$signing_key" -public-key-output "$staging/package-signing.pub" \
    -version "dev-$build_stamp-$short_commit" -commit "$commit"
else
  go run ./cmd/mwaf-bundle \
    -metadata "$staging/metadata" -packages "$staging/packages" \
    -policy-source-metadata "$staging/policy-source-metadata" -policy-sources "$staging/policy-sources" \
    -output "$staging/bundle" -key "$signing_key" -public-key-output "$staging/package-signing.pub" \
    -version "dev-$build_stamp-$short_commit" -commit "$commit" \
    -previous-bundle "$base_bundle" -previous-public-key "$base_public_key"
fi
go run ./cmd/mwaf-bundle -verify-bundle "$staging/bundle" -verify-public-key "$staging/package-signing.pub"

final="$runtime_root/dev-bundles/dev-$build_stamp-$short_commit"
mv "$staging" "$final"
published=1
printf '%s\n' "$final" > "$runtime_root/dev-bundle-current"
active_link="$runtime_root/dev-bundle-active"
ln -sfn "$final" "$active_link"
echo "Local signed development bundle: $final"
echo "Start it with: make dev-full"
