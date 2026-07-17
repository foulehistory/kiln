#!/bin/bash
# Shared launcher for the Windows .cmd wrappers (kiln.cmd, kiln-compose.cmd).
# Prefers an auto-updated, "installed" binary under $KILN_STORE/bin/ if one
# exists there (see kiln-dashboard's update-check/apply feature), falling
# back to the dev build under target/debug/ otherwise. Keeping this in one
# script - rather than inlined in each .cmd - avoids nested quote-escaping
# across cmd.exe -> wsl.exe -> bash, which was a repeated source of bugs.
NAME="$1"
shift
STORE="${KILN_STORE:-$HOME/.kiln}"
B="$STORE/bin/$NAME"
[ -x "$B" ] || B="/mnt/e/kiln/target/debug/$NAME"
exec "$B" "$@"
