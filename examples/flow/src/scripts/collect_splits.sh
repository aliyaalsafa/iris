#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 TRAIN_SECS VALIDATION_SECS TEST_SECS   (0 skips a split)" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    exec sudo env LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" OUT_ROOT="${OUT_ROOT:-}" "$0" "$@"
fi

cd "$(dirname "$0")/../../../.."

BIN=./target/release/flow_collect
CONFIG=configs/online.toml
OUT_ROOT=${OUT_ROOT:-/mnt/netdata}
export RUST_LOG=info

tmp_config="$(mktemp --suffix=.toml)"
trap 'rm -f "$tmp_config"' EXIT

write_online_config_with_duration() {
    awk -v secs="$1" '
        function flush() { if (in_online && !done) { print "duration = " secs; done = 1 } }
        /^[[:space:]]*\[/ {
            flush()
            in_online = ($0 ~ /^[[:space:]]*\[online\][[:space:]]*(#.*)?$/)
        }
        in_online && /^[[:space:]]*duration[[:space:]]*=/ {
            if (!done) { print "duration = " secs; done = 1 }
            next
        }
        { print }
        END { flush() }
    ' "$CONFIG" > "$tmp_config"
}

run_split() {
    local split=$1 secs=$2 trace=$3
    (( secs > 0 )) || return 0
    mkdir -p "$OUT_ROOT/$split"
    write_online_config_with_duration "$secs"
    echo "=== $split: ${secs}s -> $OUT_ROOT/$split (trace $trace) ==="
    FLOW_OUT_DIR="$OUT_ROOT/$split" "$BIN" --config "$tmp_config" --trace "$trace"
}

run_split train "$1" false
run_split validation "$2" false
run_split test "$3" true
