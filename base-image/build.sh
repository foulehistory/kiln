#!/bin/bash
# Builds `base:latest`: a minimal `FROM scratch` image providing a shell
# and busybox's coreutils, meant as a reusable `FROM base:latest` for
# other Kilnfiles in this repo (and elsewhere) instead of depending on
# `busybox:latest` from Docker Hub every time.
set -e
cd "$(dirname "$0")"

[ -x bin/busybox ] || ./fetch-busybox.sh

kiln build -f Kilnfile -t base:latest .
