// A tiny multiplayer "arena" server, `std`-only (same minimal-dependency
// ethos as chat-demo/server/chat-server.rs). Unlike chat-demo, this one
// demonstrates a `kiln volume`: each player's position is persisted to a
// file under `$STATE_FILE` (meant to be a mounted volume, see kiln.yaml)
// so it survives the container being removed and recreated - reconnect
// after a restart and you're still where you left off.
//
// Connect with any raw-TCP client - `nc localhost <port>` or `telnet
// localhost <port>`. After entering a name, send one command per line:
//
//   move <up|down|left|right>   move one step (u/d/l/r also work)
//   pos                         show your own position
//   who                         list connected players and positions
//   say <message>               broadcast a chat message
//   help                        show this list
//   quit                        disconnect
//
// Every line received from every client is logged to stdout (`kiln
// logs`/the dashboard's log panel), along with connects/disconnects -
// this is the "what input did they send" trail the position-tracking
// itself doesn't otherwise leave.
//
// Build: rustc --edition 2021 -O -o ../bin/game-server game-server.rs
// (see ../build.sh, which does this as part of building the image)

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

type Clients = Arc<Mutex<Vec<(String, TcpStream)>>>;
type Positions = Arc<Mutex<HashMap<String, (i32, i32)>>>;

// Explicit `.flush()` for the same reason as chat-demo: stdout is fully
// (not line-) buffered once it's redirected to a file, which is always
// the case here - without this, a burst of activity could sit unflushed
// for a long time instead of showing up promptly in `kiln logs`.
fn log(message: &str) {
    println!("{message}");
    let _ = std::io::stdout().flush();
}

fn state_path() -> String {
    std::env::var("STATE_FILE").unwrap_or_else(|_| "/data/players.txt".to_string())
}

/// One `name x y` per line - deliberately not JSON: this project's own
/// demos avoid pulling in a serde dependency just to persist a handful of
/// integers (see base-image's busybox-only rootfs and chat-demo's own
/// std-only server), and a static-musl build has no easy access to
/// crates.io to fetch one anyway.
fn load_positions(path: &str) -> HashMap<String, (i32, i32)> {
    let mut map = HashMap::new();
    let Ok(content) = fs::read_to_string(path) else { return map };
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(x), Some(y)) = (parts.next(), parts.next(), parts.next()) else { continue };
        let (Ok(x), Ok(y)) = (x.parse(), y.parse()) else { continue };
        map.insert(name.to_string(), (x, y));
    }
    map
}

fn save_positions(path: &str, positions: &HashMap<String, (i32, i32)>) {
    let mut out = String::new();
    for (name, (x, y)) in positions {
        out.push_str(&format!("{name} {x} {y}\n"));
    }
    // Best-effort: a failed write (e.g. the volume isn't mounted after
    // all) shouldn't take the whole session down, just leave state
    // un-persisted for next time - same "don't fail the game over
    // logging/persistence" spirit as chat-demo's broadcast retaining
    // clients on write failure.
    let _ = fs::write(path, out);
}

fn broadcast(clients: &Clients, from: &str, message: &str) {
    let line = format!("{from}: {message}\n");
    let mut clients = clients.lock().unwrap();
    clients.retain_mut(|(_, stream)| stream.write_all(line.as_bytes()).is_ok());
}

fn sanitize_name(raw: &str) -> String {
    let name: String = raw.split_whitespace().collect::<Vec<_>>().join("_");
    if name.is_empty() { "anonymous".to_string() } else { name }
}

const HELP: &str = "commands: move <up|down|left|right>, pos, who, say <message>, help, quit\n";

fn handle_client(stream: TcpStream, clients: Clients, positions: Positions) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".to_string());

    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = writer.write_all(b"Welcome to kiln-arena! Enter your name: ");

    let mut reader = BufReader::new(stream);
    let mut name_line = String::new();
    if reader.read_line(&mut name_line).is_err() {
        return;
    }
    let name = sanitize_name(&name_line);

    let pos = {
        let mut positions = positions.lock().unwrap();
        *positions.entry(name.clone()).or_insert((0, 0))
    };

    {
        let mut list = clients.lock().unwrap();
        let Ok(handle) = reader.get_ref().try_clone() else { return };
        list.push((name.clone(), handle));
    }
    log(&format!("+ {name} connected ({peer}) at ({}, {})", pos.0, pos.1));
    broadcast(&clients, "server", &format!("{name} entered the arena at ({}, {})", pos.0, pos.1));
    let _ = writer.write_all(format!("You are at ({}, {}).\n{HELP}", pos.0, pos.1).as_bytes());

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                log(&format!("< {name}: {line}"));

                let mut parts = line.splitn(2, char::is_whitespace);
                let cmd = parts.next().unwrap_or("").to_lowercase();
                let arg = parts.next().unwrap_or("").trim();

                match cmd.as_str() {
                    "move" | "m" => {
                        let delta = match arg.to_lowercase().as_str() {
                            "up" | "u" => Some((0, -1)),
                            "down" | "d" => Some((0, 1)),
                            "left" | "l" => Some((-1, 0)),
                            "right" | "r" => Some((1, 0)),
                            _ => None,
                        };
                        match delta {
                            Some((dx, dy)) => {
                                let path = state_path();
                                let new_pos = {
                                    let mut positions = positions.lock().unwrap();
                                    let entry = positions.entry(name.clone()).or_insert((0, 0));
                                    entry.0 += dx;
                                    entry.1 += dy;
                                    let new_pos = *entry;
                                    save_positions(&path, &positions);
                                    new_pos
                                };
                                let _ = writer.write_all(format!("You are now at ({}, {}).\n", new_pos.0, new_pos.1).as_bytes());
                                broadcast(&clients, "server", &format!("{name} moved to ({}, {})", new_pos.0, new_pos.1));
                            }
                            None => {
                                let _ = writer.write_all(b"usage: move <up|down|left|right>\n");
                            }
                        }
                    }
                    "pos" | "p" => {
                        let pos = *positions.lock().unwrap().get(&name).unwrap_or(&(0, 0));
                        let _ = writer.write_all(format!("You are at ({}, {}).\n", pos.0, pos.1).as_bytes());
                    }
                    "who" | "w" => {
                        let positions = positions.lock().unwrap();
                        let connected: Vec<String> = clients.lock().unwrap().iter().map(|(n, _)| n.clone()).collect();
                        let mut reply = format!("{} player(s) online:\n", connected.len());
                        for n in &connected {
                            let (x, y) = positions.get(n).copied().unwrap_or((0, 0));
                            reply.push_str(&format!("  {n} at ({x}, {y})\n"));
                        }
                        let _ = writer.write_all(reply.as_bytes());
                    }
                    "say" if !arg.is_empty() => broadcast(&clients, &name, arg),
                    "help" | "h" | "?" => {
                        let _ = writer.write_all(HELP.as_bytes());
                    }
                    "quit" | "exit" | "q" => break,
                    _ => {
                        let _ = writer.write_all(format!("unknown command {cmd:?}. {HELP}").as_bytes());
                    }
                }
            }
        }
    }

    clients.lock().unwrap().retain(|(n, _)| n != &name);
    log(&format!("- {name} disconnected ({peer})"));
    broadcast(&clients, "server", &format!("{name} left the arena"));
}

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(7000);
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");

    let path = state_path();
    let positions: Positions = Arc::new(Mutex::new(load_positions(&path)));
    log(&format!(
        "kiln-arena listening on :{port} ({} saved player position(s) loaded from {path})",
        positions.lock().unwrap().len()
    ));

    let clients: Clients = Arc::new(Mutex::new(Vec::new()));
    for stream in listener.incoming().flatten() {
        let clients = clients.clone();
        let positions = positions.clone();
        thread::spawn(move || handle_client(stream, clients, positions));
    }
}
