# `base:latest`

A minimal `FROM scratch` image providing a working shell (`/bin/sh`) and
busybox's coreutils (`ls`, `cat`, `grep`, `sed`, `mkdir`, `wget`, ...) -
meant to be a reusable base for other Kilnfiles in this project (and
elsewhere), instead of depending on `busybox:latest` from Docker Hub every
time something needs to be built or tested.

## Build it

```sh
./build.sh
```

This produces a local image tagged `base:latest`. Use it in another
Kilnfile the same way you'd use any other base:

```
FROM base:latest
RUN echo hello > /proof.txt
```

## Push it

Like any other locally built image, it can be pushed to a registry (e.g.
the mini-registry example under `kiln-image/examples/mini-registry.rs`):

```sh
kiln push base:latest
```

## Provenance

`bin/busybox` is the real `busybox` binary extracted from Docker Hub's
official `busybox:1.38.0-musl` image (musl, not glibc/uclibc, because
musl builds are the ones actually linked fully static - required for a
binary that has to run inside `FROM scratch`, which has no dynamic linker
at all). Every other file under `bin/` is a symlink to `busybox` itself -
busybox dispatches on the invoked name (`argv[0]`), so `bin/ls`, `bin/sh`,
`bin/grep`, etc. are all the same ~1MB binary. See `fetch-busybox.sh` for
exactly how it was fetched; that script is a one-shot vendoring step, not
something `build.sh` needs to re-run unless bumping the pinned version.

Busybox itself is GPLv2. This binary is committed to the repo as-is,
unmodified, exactly as distributed by Docker Hub's official image.
