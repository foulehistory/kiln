# `chat-server:latest`

A tiny multi-user TCP chat server - every connected client's lines get
broadcast to every other client, like an IRC channel with no commands.
Built `FROM base:latest` (see `../base-image/`) as a fully static musl
binary, since `base:latest` has no libc at all to dynamically link
against.

## Build it

```sh
./build.sh
```

(needs the musl target once: `rustup target add x86_64-unknown-linux-musl`)

## Run it

Needs a network and a published port, so the chat is actually reachable
from the host:

```sh
kiln network create chatnet
kiln run -d --name chat --network chatnet -p 6667:6667 chat-server:latest
```

## Connect

From any terminal, with any raw-TCP client - no special chat client
needed:

```sh
nc localhost 6667
# or: telnet localhost 6667
```

Type a name when prompted, then just type messages - every other
connected client sees them prefixed with your name. Open a second
terminal and connect again to see it actually broadcast between clients.

On Windows: WSL's bash has `nc` (or `busybox nc`) available directly.
Native `cmd`/PowerShell needs the Telnet Client optional feature enabled
(`dism /online /Enable-Feature /FeatureName:TelnetClient` from an admin
prompt, or via "Turn Windows features on or off") - Windows doesn't ship
an `nc` equivalent out of the box.

## Clean up

```sh
kiln rm -f chat
kiln network rm chatnet
```
