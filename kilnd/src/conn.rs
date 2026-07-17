//! A connection accepted on either listener `kilnd` runs, unified behind
//! one `Read + Write` type so `http.rs`/`handlers/*` don't need to care
//! which one a given request arrived on.
//!
//! `kilnd` listens on **both** a Unix socket (the primary, permission-
//! controlled path - see `cgroup`/namespace operations that already
//! require root) and a loopback TCP port. The TCP listener exists
//! specifically so `kiln-dashboard`, when run as a native Windows
//! Electron app rather than inside WSL, can still reach it: WSL2
//! forwards `localhost` ports to Windows automatically, but a Unix
//! domain socket living inside the WSL2 VM's filesystem is not
//! reachable from Windows-side code at all (it's a different kernel).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;

pub enum Conn {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Conn {
    pub fn try_clone(&self) -> io::Result<Conn> {
        match self {
            Conn::Unix(s) => Ok(Conn::Unix(s.try_clone()?)),
            Conn::Tcp(s) => Ok(Conn::Tcp(s.try_clone()?)),
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Unix(s) => s.read(buf),
            Conn::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Unix(s) => s.write(buf),
            Conn::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Unix(s) => s.flush(),
            Conn::Tcp(s) => s.flush(),
        }
    }
}
