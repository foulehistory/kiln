#!/bin/bash
# Builds `game-server:latest`: a tiny multiplayer "arena" server (see
# server/game-server.rs) that persists player positions to a `kiln
# volume`, FROM this repo's own base:latest.
#
# Needs the musl target installed once (`rustup target add
# x86_64-unknown-linux-musl`) so the binary comes out fully static -
# base:latest has no libc at all (it's built on busybox), so a normally
# glibc-linked binary wouldn't run in it.
set -e
cd "$(dirname "$0")"
mkdir -p bin

rustc --edition 2021 -O --target x86_64-unknown-linux-musl \
  -o bin/game-server server/game-server.rs
strip bin/game-server

kiln build -f Kilnfile -t game-server:latest .
