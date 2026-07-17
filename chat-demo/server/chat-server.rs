// A minimal multi-user TCP chat server, `std`-only (no dependencies to
// build, matching this project's own minimal-dependency ethos - see
// kilnd/kiln-cli/kiln-image, none of which pull in a web/async framework
// for what a few hundred lines of std can do). Every connected client's
// lines get broadcast to every other client, like an IRC channel with no
// commands. Connect with any raw-TCP client - `nc localhost <port>` or
// `telnet localhost <port>` - no special chat client needed.
//
// Build: rustc --edition 2021 -O -o ../bin/chat-server chat-server.rs
// (see ../build.sh, which does this as part of building the image)

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

type Clients = Arc<Mutex<Vec<(String, TcpStream)>>>;

fn broadcast(clients: &Clients, from: &str, message: &str) {
    let line = format!("{from}: {message}\n");
    let mut clients = clients.lock().unwrap();
    clients.retain_mut(|(_, stream)| stream.write_all(line.as_bytes()).is_ok());
}

// Logged to stdout, which kilnd captures into the container's log file
// (`kiln logs`, and the dashboard's log panel) the same as anything else
// the container prints - explicit `.flush()` because Rust's stdout is
// only *line*-buffered when it detects a real terminal; redirected to a
// file (what it always is here), it's fully buffered by default, so
// without this a connect/disconnect line could sit unflushed for a long
// time instead of showing up promptly.
fn log(message: &str) {
    println!("{message}");
    let _ = std::io::stdout().flush();
}

fn handle_client(stream: TcpStream, clients: Clients) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".to_string());

    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = writer.write_all(b"Welcome to kiln-chat! Enter your name: ");

    let mut reader = BufReader::new(stream);
    let mut name = String::new();
    if reader.read_line(&mut name).is_err() {
        return;
    }
    let name = name.trim();
    let name = if name.is_empty() { "anonymous" } else { name }.to_string();

    {
        let mut list = clients.lock().unwrap();
        let Ok(handle) = reader.get_ref().try_clone() else { return };
        list.push((name.clone(), handle));
    }
    log(&format!("+ {name} connected ({peer})"));
    broadcast(&clients, "server", &format!("{name} joined the chat"));

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = line.trim();
                if !line.is_empty() {
                    broadcast(&clients, &name, line);
                }
            }
        }
    }

    clients.lock().unwrap().retain(|(n, _)| n != &name);
    log(&format!("- {name} disconnected ({peer})"));
    broadcast(&clients, "server", &format!("{name} left the chat"));
}

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(6667);
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    log(&format!("kiln-chat listening on :{port}"));

    let clients: Clients = Arc::new(Mutex::new(Vec::new()));
    for stream in listener.incoming().flatten() {
        let clients = clients.clone();
        thread::spawn(move || handle_client(stream, clients));
    }
}
