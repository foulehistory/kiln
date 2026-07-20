#!/bin/sh
# Rebuilds kiln-net-bpf and copies the result into dist/, where
# kilnd-core's netbpf.rs embeds it via include_bytes!. Run this after any
# change to src/main.rs and commit the updated dist/kiln-net-bpf.o - the
# rest of the workspace builds on stable Rust and can't compile this
# no_std, bpfel-unknown-none crate itself (see Cargo.toml's [workspace]
# comment for why it isn't a normal workspace member).
#
# Needs: rustup toolchain install nightly --component rust-src,
# and `cargo install bpf-linker` (which itself needs LLVM dev headers,
# e.g. `apt-get install llvm-21-dev` on Debian/Ubuntu).
set -eu
cd "$(dirname "$0")"
cargo build --release
cp target/bpfel-unknown-none/release/kiln-net-bpf dist/kiln-net-bpf.o
echo "wrote dist/kiln-net-bpf.o"
