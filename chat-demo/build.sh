#!/bin/bash
# Builds `chat-server:latest`: a tiny multi-user TCP chat server (see
# server/chat-server.rs), FROM this repo's own base:latest.
#
# Needs the musl target installed once (`rustup target add
# x86_64-unknown-linux-musl`) so the binary comes out fully static -
# base:latest has no libc at all (it's built on busybox), so a normally
# glibc-linked binary wouldn't run in it.
set -e
cd "$(dirname "$0")"

rustc --edition 2021 -O --target x86_64-unknown-linux-musl \
  -o bin/chat-server server/chat-server.rs
strip bin/chat-server

kiln build -f Kilnfile -t chat-server:latest .
