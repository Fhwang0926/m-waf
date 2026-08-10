#!/bin/sh
set -eu

version_file=packaging/agent/VERSION
[ -f "$version_file" ] || { echo "$version_file is required" >&2; exit 1; }
version=$(sed -n '1p' "$version_file")
case "$version" in
  ''|*[!0-9.]*|.*|*..*|*.) echo "Agent VERSION must use MAJOR.MINOR.PATCH" >&2; exit 1 ;;
esac
[ "$(printf '%s' "$version" | awk -F. '{print NF}')" -eq 3 ] || { echo "Agent VERSION must use MAJOR.MINOR.PATCH" >&2; exit 1; }

base_ref=${1:-}
[ -n "$base_ref" ] || { echo "Agent VERSION $version"; exit 0; }
git cat-file -e "$base_ref:$version_file" 2>/dev/null || { echo "Agent VERSION $version (no base VERSION to compare)"; exit 0; }
base_version=$(git show "$base_ref:$version_file" | sed -n '1p')
changed=$(git diff --name-only "$base_ref"...HEAD -- \
  cmd/mwaf-agent internal/agent internal/config internal/model internal/protocol packaging/agent go.mod go.sum)
[ -n "$changed" ] || { echo "Agent sources unchanged"; exit 0; }
[ "$version" != "$base_version" ] || {
  echo "Agent sources changed but packaging/agent/VERSION is still $version" >&2
  printf '%s\n' "$changed" >&2
  exit 1
}

version_number() { printf '%s' "$1" | awk -F. -v part="$2" '{print $part+0}'; }
for part in 1 2 3; do
  current_part=$(version_number "$version" "$part")
  base_part=$(version_number "$base_version" "$part")
  if [ "$current_part" -gt "$base_part" ]; then
    echo "Agent VERSION $base_version -> $version"
    exit 0
  fi
  if [ "$current_part" -lt "$base_part" ]; then
    echo "Agent VERSION must increase: base=$base_version current=$version" >&2
    exit 1
  fi
done
echo "Agent VERSION must increase: base=$base_version current=$version" >&2
exit 1
