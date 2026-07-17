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

**Via `kiln-compose`** (simplest - `kiln.yaml` already declares the
network and the published port):

```sh
kiln-compose up -d
```

**Or by hand**, if you want to see each piece:

```sh
kiln network create chatnet
kiln run -d --name chat --network chatnet -p 6668:6667 chat-server:latest
```

Either way, the chat ends up reachable on host port `6668`.

## Connect

From any terminal, with any raw-TCP client - no special chat client
needed:

```sh
nc localhost 6668
# or: telnet localhost 6668
```

Type a name when prompted, then just type messages - every other
connected client sees them prefixed with your name. Open a second
terminal and connect again to see it actually broadcast between clients.

On Windows: WSL's bash has `nc` (or `busybox nc`) available directly.
Native `cmd`/PowerShell needs the Telnet Client optional feature enabled
(`Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient` from
an admin PowerShell, or via "Turn Windows features on or off") - Windows
doesn't ship an `nc` equivalent out of the box.

To let someone outside your LAN connect (e.g. over your public IP),
you need two extra hops beyond your router's port forwarding, because
`kiln`/`kilnd` run inside WSL2, which has its own virtual network:
forward the external port to your Windows machine's LAN IP on your
router, then bridge that into WSL2 with
`netsh interface portproxy add v4tov4 listenport=6668 listenaddress=0.0.0.0
connectport=6668 connectaddress=<WSL2 IP from `wsl hostname -I`>` and an
inbound Windows Firewall rule for that port. WSL2's automatic
`localhost`-forwarding only covers traffic already arriving on
`127.0.0.1`, not traffic arriving from the outside on a real interface.

## Clean up

```sh
kiln-compose down
# or, if started by hand:
kiln rm -f chat
kiln network rm chatnet
```
