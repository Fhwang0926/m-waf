#!/bin/sh
set -eu

repository_root=${1:?repository root is required}
manager_binary=${2:?manager binary path is required}
candidate_binary="$manager_binary.next"
manager_pid=

source_stamp() {
  {
    find \
      "$repository_root/cmd/mwaf-manager" \
      "$repository_root/internal" \
      "$repository_root/migrations" \
      "$repository_root/web" \
      "$repository_root/go.mod" \
      "$repository_root/go.sum" \
      -type f -exec cksum {} \;
    if [ -n "${MWAF_BUNDLE_ROOT:-}" ] && [ -f "$MWAF_BUNDLE_ROOT/bundle-manifest.json" ]; then
      printf '%s\n' "$(readlink "${MWAF_BUNDLE_ROOT%/bundle}" 2>/dev/null || true)"
      cksum "$MWAF_BUNDLE_ROOT/bundle-manifest.json"
    fi
  } | cksum | awk '{ print $1 ":" $2 }'
}

build_manager() {
  echo "Source change detected; rebuilding Manager..."
  (cd "$repository_root" && go build -o "$candidate_binary" ./cmd/mwaf-manager)
}

start_manager() {
  "$manager_binary" &
  manager_pid=$!
  echo "Manager is running. Waiting for source changes..."
}

stop_manager() {
  if [ -n "$manager_pid" ] && kill -0 "$manager_pid" 2>/dev/null; then
    kill "$manager_pid"
    wait "$manager_pid" 2>/dev/null || true
  fi
  manager_pid=
}

shutdown() {
  stop_manager
  exit 0
}

trap shutdown INT TERM HUP

last_stamp=$(source_stamp)
build_manager
mv "$candidate_binary" "$manager_binary"
start_manager

while :
do
  sleep 1
  current_stamp=$(source_stamp)
  if [ "$current_stamp" != "$last_stamp" ]; then
    last_stamp=$current_stamp
    if build_manager; then
      stop_manager
      mv "$candidate_binary" "$manager_binary"
      start_manager
    else
      echo "Manager rebuild failed; the current process remains available. Fix the error and save again." >&2
    fi
  fi
  if [ -n "$manager_pid" ] && ! kill -0 "$manager_pid" 2>/dev/null; then
    wait "$manager_pid" 2>/dev/null || true
    manager_pid=
    echo "Manager stopped. It will restart after the next source change." >&2
  fi
done
