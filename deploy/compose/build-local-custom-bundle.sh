#!/bin/sh
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
source_dir=${MWAF_DEV_CUSTOM_SOURCE_DIR:-}
[ -n "$source_dir" ] || { echo "MWAF_DEV_CUSTOM_SOURCE_DIR is required" >&2; exit 2; }
case "$source_dir" in /*) ;; *) source_dir="$repository_root/$source_dir" ;; esac
[ -d "$source_dir" ] || { echo "custom module source directory does not exist: $source_dir" >&2; exit 1; }

for required in go git jq
do
  command -v "$required" >/dev/null 2>&1 || { echo "$required is required" >&2; exit 1; }
done

runtime_root=${MWAF_DEV_RUNTIME_DIR:-$repository_root/.local/mwaf-manager}
mkdir -p "$runtime_root"
generated=$(mktemp -d "$runtime_root/.custom-modules.XXXXXX")
trap 'rm -rf "$generated"' EXIT HUP INT TERM
mkdir -p "$generated/packages" "$generated/metadata"

commit=$(git -C "$repository_root" rev-parse HEAD)
short_commit=$(printf '%s' "$commit" | cut -c1-12)
build_stamp=$(date -u +%Y%m%d%H%M%S)
build_suffix="${build_stamp}.${short_commit}.$$"
target_count=0

for spec in "$source_dir"/*/spec.json
do
  [ -f "$spec" ] || continue
  target_root=${spec%/spec.json}
  payload="$target_root/payload"
  [ -d "$payload/module" ] && [ -f "$payload/integration/mwaf.conf" ] || { echo "custom target requires payload/module and payload/integration/mwaf.conf: $target_root" >&2; exit 1; }
  jq -e '
    (.id | type == "string" and length > 0) and
    (.version | type == "string" and length > 0) and
    (.os_id | type == "string" and length > 0) and
    (.os_version | type == "string" and length > 0) and
    (.web_server == "apache" or .web_server == "nginx") and
    (.web_server_version | type == "string" and length > 0) and
    (.web_server_build_hash | type == "string" and test("^[0-9A-Fa-f]{64}$")) and
    (.runtime_abi | type == "string" and length > 0)
  ' "$spec" >/dev/null || { echo "invalid custom module spec: $spec" >&2; exit 1; }

  base_id=$(jq -r '.id' "$spec")
  base_version=$(jq -r '.version' "$spec")
  os_id=$(jq -r '.os_id' "$spec")
  os_version=$(jq -r '.os_version' "$spec")
  web_server=$(jq -r '.web_server' "$spec")
  web_server_version=$(jq -r '.web_server_version' "$spec")
  web_server_build=$(jq -r '.web_server_build_hash' "$spec")
  runtime_abi=$(jq -r '.runtime_abi' "$spec")
  case "$base_id$base_version" in *[!0-9A-Za-z._+~-]*) echo "custom module id and version contain unsupported characters: $spec" >&2; exit 1 ;; esac

  artifact_id="${base_id}-dev-${build_stamp}-${short_commit}-$$"
  artifact_version="${base_version}+dev.${build_suffix}"
  package_name="${artifact_id}.zip"
  metadata_name="${artifact_id}.json"
  (
    cd "$repository_root"
    go run ./cmd/mwaf-module-zip \
      -input "$payload" \
      -output "$generated/packages/$package_name" \
      -metadata-output "$generated/metadata/$metadata_name" \
      -id "$artifact_id" \
      -version "$artifact_version" \
      -os-id "$os_id" \
      -os-version "$os_version" \
      -webserver "$web_server" \
      -webserver-version "$web_server_version" \
      -webserver-build "$web_server_build" \
      -runtime-abi "$runtime_abi"
  )
  target_count=$((target_count + 1))
  echo "Prepared $web_server $web_server_version custom module for $os_id $os_version"
done

[ "$target_count" -gt 0 ] || { echo "no */spec.json custom module targets were found in $source_dir" >&2; exit 1; }
MWAF_DEV_CUSTOM_PACKAGES_DIR="$generated" MWAF_DEV_AGENT_ONLY=false sh "$script_dir/build-local-bundle.sh"
echo "Custom module development bundle activated for $target_count target(s). Refresh the server package page to install it."
