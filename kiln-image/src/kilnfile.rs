//! Parser for the Kilnfile format: a deliberately small, Dockerfile-shaped
//! instruction set (`FROM`, `RUN`, `COPY`, `ENV`, `CMD`, `EXPOSE`,
//! `WORKDIR`). This module only turns text into structured
//! [`Instruction`]s; see `build.rs` for what each instruction actually
//! does and, critically, how it affects build cache invalidation.
//!
//! Syntax, precisely:
//!
//! - One instruction per logical line: `VERB rest-of-line`. The verb is
//!   case-insensitive by convention but written uppercase.
//! - Blank lines and lines starting with `#` (after trimming leading
//!   whitespace) are ignored.
//! - A line ending in `\` continues onto the next line (its trailing `\`
//!   is dropped and replaced with a single space) - useful for long `RUN`
//!   commands, exactly like a Dockerfile.
//! - `RUN <command>` is always shell form: the command is passed to
//!   `/bin/sh -c`. There is no exec-form (`RUN ["a", "b"]`) - keeping one
//!   unambiguous form avoids a whole class of Dockerfile confusion around
//!   which form does/doesn't invoke a shell.
//! - `COPY <src> <dst>` takes exactly two whitespace-separated arguments.
//!   Multi-source `COPY` (`COPY a b c dst/`) is not supported.
//! - `ENV key=value` or `ENV key value` (both accepted).
//! - `EXPOSE <port>` or `EXPOSE <port>/<proto>` (default proto `tcp`).

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    From { image: String },
    Run { command: String },
    Copy { src: String, dst: String },
    Env { key: String, value: String },
    Cmd { command: String },
    Expose { port: u16, proto: String },
    Workdir { path: String },
}

pub fn parse(source: &str) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    let mut pending = String::new();
    let mut start_line = 1;

    for (i, raw_line) in source.lines().enumerate() {
        let line_no = i + 1;
        let line = raw_line.trim_end();
        if pending.is_empty() {
            start_line = line_no;
        }

        if let Some(stripped) = line.strip_suffix('\\') {
            pending.push_str(stripped.trim_end());
            pending.push(' ');
            continue;
        }

        pending.push_str(line);
        let full = std::mem::take(&mut pending);
        let trimmed = full.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(parse_instruction(trimmed, start_line)?);
    }

    if !pending.trim().is_empty() {
        return Err(Error::KilnfileParse {
            line: start_line,
            message: "file ends mid line-continuation (trailing '\\' with nothing after it)".into(),
        });
    }

    Ok(out)
}

fn parse_instruction(line: &str, line_no: usize) -> Result<Instruction> {
    let (verb, rest) = line.split_once(char::is_whitespace).map(|(v, r)| (v, r.trim())).unwrap_or((line, ""));

    let err = |message: String| Error::KilnfileParse { line: line_no, message };

    match verb.to_ascii_uppercase().as_str() {
        "FROM" => {
            if rest.is_empty() {
                return Err(err("FROM requires an image reference".into()));
            }
            Ok(Instruction::From { image: rest.to_string() })
        }
        "RUN" => {
            if rest.is_empty() {
                return Err(err("RUN requires a command".into()));
            }
            Ok(Instruction::Run { command: rest.to_string() })
        }
        "COPY" => {
            let mut parts = rest.split_whitespace();
            let src = parts.next().ok_or_else(|| err("COPY requires <src> <dst>".into()))?;
            let dst = parts.next().ok_or_else(|| err("COPY requires <src> <dst>".into()))?;
            if parts.next().is_some() {
                return Err(err("COPY takes exactly two arguments (multi-source COPY is not supported)".into()));
            }
            Ok(Instruction::Copy {
                src: src.to_string(),
                dst: dst.to_string(),
            })
        }
        "ENV" => {
            if let Some((k, v)) = rest.split_once('=') {
                Ok(Instruction::Env {
                    key: k.trim().to_string(),
                    value: v.trim().to_string(),
                })
            } else if let Some((k, v)) = rest.split_once(char::is_whitespace) {
                Ok(Instruction::Env {
                    key: k.trim().to_string(),
                    value: v.trim().to_string(),
                })
            } else {
                Err(err("ENV requires key=value or key value".into()))
            }
        }
        "CMD" => {
            if rest.is_empty() {
                return Err(err("CMD requires a command".into()));
            }
            Ok(Instruction::Cmd { command: rest.to_string() })
        }
        "EXPOSE" => {
            let (port_str, proto) = match rest.split_once('/') {
                Some((p, proto)) => (p, proto.to_string()),
                None => (rest, "tcp".to_string()),
            };
            let port: u16 = port_str.trim().parse().map_err(|_| err(format!("invalid port {port_str:?}")))?;
            Ok(Instruction::Expose { port, proto })
        }
        "WORKDIR" => {
            if rest.is_empty() {
                return Err(err("WORKDIR requires a path".into()));
            }
            Ok(Instruction::Workdir { path: rest.to_string() })
        }
        other => Err(err(format!(
            "unknown instruction {other:?} (expected one of FROM, RUN, COPY, ENV, CMD, EXPOSE, WORKDIR)"
        ))),
    }
}
