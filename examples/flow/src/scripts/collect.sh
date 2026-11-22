#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [DURATION_SECS]   (omit to run until Ctrl-C)" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    exec sudo env LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" OUT_ROOT="${OUT_ROOT:-}" "$0" "$@"
fi

cd "$(dirname "$0")/../../../.."

BIN=./target/release/flow_collect
CONFIG=configs/online.toml
OUT_ROOT=${OUT_ROOT:-/mnt/netdata}
OUT_DIR="$OUT_ROOT/run_$(date +%Y%m%dT%H%M%S)"
export RUST_LOG=info

tmp_config="$(mktemp --suffix=.toml)"
trap 'rm -f "$tmp_config"' EXIT

write_online_config_with_duration() {
    awk -v secs="$1" '
        function flush() { if (in_online && !done && secs != "") { print "duration = " secs; done = 1 } }
        /^[[:space:]]*\[/ {
            flush()
            in_online = ($0 ~ /^[[:space:]]*\[online\][[:space:]]*(#.*)?$/)
        }
        in_online && /^[[:space:]]*duration[[:space:]]*=/ {
            if (!done && secs != "") { print "duration = " secs; done = 1 }
            next
        }
        { print }
        END { flush() }
    ' "$CONFIG" > "$tmp_config"
}

mkdir -p "$OUT_DIR"
write_online_config_with_duration "${1:-}"
run_length=${1:+${1}s}
echo "=== ${run_length:-until Ctrl-C} -> $OUT_DIR ==="
"$BIN" --config "$tmp_config" --out-dir "$OUT_DIR"
