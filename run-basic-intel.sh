#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/etinfo/users2/tyunyayev/Workspace/iris"
DPDK_INSTALL="/etinfo/users2/tyunyayev/Workspace/dpdk-25.11/install_$(hostname)"
DPDK_LIB="${DPDK_INSTALL}/lib/x86_64-linux-gnu"

cd "${REPO_ROOT}"

# Build env (used both for compile and run).
export IRIS_HOME="${REPO_ROOT}"
export DPDK_PATH="${DPDK_INSTALL}"
export DPDK_VERSION="25.11"
export LD_LIBRARY_PATH="${DPDK_LIB}"
export PKG_CONFIG_PATH="${DPDK_LIB}/pkgconfig"
export LIBCLANG_PATH="/usr/lib/llvm-18/lib"
export PATH="/usr/lib/llvm-18/bin:${PATH}"

CONFIG="${1:-configs/online-intel.toml}"

echo "==> Building basic example (release) ..."
cargo +nightly build --release -p basic --locked

echo "==> Running with config: ${CONFIG}"
sudo \
    LD_LIBRARY_PATH="${DPDK_LIB}" \
    IRIS_HOME="${IRIS_HOME}" \
    RUST_LOG="${RUST_LOG:-info}" \
    "${REPO_ROOT}/target/release/basic" --config "${CONFIG}"
