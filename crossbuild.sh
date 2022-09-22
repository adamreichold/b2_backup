#!/bin/bash -xe

: "${ARCH:=arm64}"
: "${TARGET:=aarch64-unknown-linux-gnu}"
: "${TARGET_CPU:=cortex-a53}"
: "${TARGET_CC:=aarch64-linux-gnu-gcc}"

podman run --interactive --rm --volume $PWD:/src rust:bullseye /bin/bash -xe <<EOF

export DEBIAN_FRONTEND="noninteractive"

apt-get update
apt-get install --yes --no-install-recommends crossbuild-essential-${ARCH} libclang-dev

export CARGO_TARGET_DIR="target-crossbuild-${ARCH}"
export RUSTFLAGS="-Clinker=${TARGET_CC} -Ctarget-cpu=${TARGET_CPU}"
export TARGET_CC="${TARGET_CC}"

cd /src
rustup target add ${TARGET}
cargo build --no-default-features --release --target=${TARGET}

EOF
