#!/bin/bash
# One-shot vendoring script: pulls a pinned busybox image via `kiln`,
# extracts the real binary out of a running container of it (there's no
# "extract a file from an image" command, so this reuses the exact same
# pull/run/cp/rm commands any user already has), and builds the applet
# symlink farm on the *host* filesystem - not via a Kilnfile `RUN` step,
# since every `RUN` gets a fresh, unconfigured network namespace (even
# loopback down) and couldn't reach Docker Hub itself, and because
# building the symlinks ahead of time avoids relying on `busybox
# --install` behaving correctly against a `/bin/sh` that a Kilfile COPY
# already placed there (untested, and `kiln-image`'s build treats any
# non-zero exit as a hard failure).
#
# Run this once; the result (base-image/bin/) is committed to the repo,
# so this script normally never needs to run again unless bumping the
# pinned busybox version below.
set -e

# Pinned (not :latest) so this vendoring step is reproducible - re-running
# it later always fetches the exact same bytes. musl, not glibc/uclibc:
# busybox's musl builds are the variant actually linked fully static, which
# is what lets the binary run with zero shared-library dependencies inside
# a `FROM scratch` image that has no dynamic linker at all.
TAG="busybox:1.38.0-musl"

cd "$(dirname "$0")"

kiln pull "$TAG"
kiln run -d --name busybox-fetch "$TAG" sleep 30
kiln cp busybox-fetch:/bin/busybox bin/busybox
kiln rm -f busybox-fetch

# `kiln cp` (container -> host) doesn't preserve the source file's mode -
# it writes through a plain O_CREAT, so the extracted binary lands
# non-executable even though it's executable inside the container.
chmod +x bin/busybox

cd bin
for applet in $(./busybox --list); do
  [ "$applet" = "busybox" ] && continue
  ln -sf busybox "$applet"
done

echo "vendored $(./busybox | head -1) with $(ls -1 | wc -l) applets into base-image/bin/"
