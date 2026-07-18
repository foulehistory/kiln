# `game-server:latest`

A tiny multiplayer "arena" server - connect, move around a 2D grid,
chat, and see who else is online. Unlike `chat-demo`, this one
demonstrates a `kiln volume`: every player's position is persisted to a
file under `/data` (a mounted volume, not the container's own writable
layer), so it survives `kiln rm`/recreation - reconnect after the
container's been rebuilt and you're still where you left off. Every
connect, disconnect, and command a player sends is also logged to
stdout (`kiln logs` / the dashboard's log panel).

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
volume and the published port):

```sh
kiln-compose up -d
```

**Or by hand**, if you want to see each piece:

```sh
kiln network create arenanet
kiln volume create arena-data
kiln run -d --name arena --network arenanet -v arena-data:/data -p 7001:7000 game-server:latest
```

Either way, the arena ends up reachable on host port `7001`.

## Connect

From any terminal, with any raw-TCP client:

```sh
nc localhost 7001
# or: telnet localhost 7001
```

Type a name when prompted, then send one command per line:

```
move up          (aliases: move u / move down / move d / move left / move l / move right / move r)
pos              show your own position
who              list connected players and their positions
say <message>    broadcast a chat message to everyone else
help             show this list
quit             disconnect
```

Open a second terminal and connect again (with a different name) to see
`who`/movement broadcasts actually work between two players.

## See the volume in action

```sh
# move around, note your position with `pos`, then disconnect
kiln-compose down          # removes the container entirely
kiln-compose up -d         # recreate it from scratch
```

Reconnect with the *same name* and `pos` shows the same coordinates -
the container is brand new, but `/data/players.txt` (inside the
`arena-data` volume) never went away. Removing the volume too
(`kiln volume rm arena-data` after `kiln-compose down`) resets everyone
back to `(0, 0)`.

## Clean up

```sh
kiln-compose down
# or, if started by hand:
kiln rm -f arena
kiln volume rm arena-data
```
