//! `.env` support for `kiln.yaml`: a file next to the compose file whose
//! `KEY=value` lines are available for `${VAR}` interpolation in the
//! compose file's own text - matching docker-compose's actual
//! behavior, not the common misconception that `.env` values also
//! become container environment variables automatically (that's
//! `env_file:`, a distinct, unrelated feature this project doesn't
//! implement). A service that wants a `.env` value inside its own
//! container must say so explicitly, e.g.
//! `environment: { DB_PASS: "${DB_PASS}" }` - interpolation replaces
//! that before `serde_yaml` ever sees the file.

use std::collections::BTreeMap;
use std::path::Path;

/// Reads `.env` from `dir` (the compose file's own directory - docker-
/// compose's convention), returning an empty map if it doesn't exist at
/// all (silent - a project without a `.env` isn't an error). `KEY=value`
/// per line; blank lines and lines starting with `#` (after trimming
/// leading whitespace) are skipped. No quoting/escaping support within
/// values - deliberately minimal, same spirit as `interpolate`'s own
/// documented scope limit below.
pub fn load(dir: &Path) -> BTreeMap<String, String> {
    let Ok(content) = std::fs::read_to_string(dir.join(".env")) else {
        return BTreeMap::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            line.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Substitutes `${VAR}`, `${VAR:-default}`, and `${VAR:?message}` in
/// `source`. Real shell environment variables (`std::env::var`) take
/// priority over `dotenv`, matching docker-compose's own precedence -
/// `.env` provides defaults, not overrides, so `FOO=x kiln-compose up`
/// still wins over a `.env` line setting `FOO`. An empty-but-set
/// variable is treated the same as unset for the `:-`/`:?` forms (POSIX
/// shell's own `:`-prefixed semantics). `$$` is a literal `$`, an escape
/// for a `${...}` that must reach kiln.yaml's own consumer unexpanded -
/// e.g. a container's own shell command meant to expand a variable
/// itself, not have kiln-compose expand it first.
///
/// Deliberately narrow scope: only these three forms (no bare `$VAR`
/// without braces, no `${VAR-default}`/`${VAR+alt}` variants) - same
/// spirit as this project's own duration-parsing scope limit elsewhere
/// (see `compose::parse_duration_secs`).
pub fn interpolate(source: &str, dotenv: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'$') {
            out.push('$');
            i += 2;
            continue;
        }
        if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'{') {
            let end = source[i + 2..]
                .find('}')
                .ok_or_else(|| format!("unterminated \"${{\" (no closing \"}}\") starting at byte {i}"))?;
            let inner = &source[i + 2..i + 2 + end];
            out.push_str(&resolve(inner, dotenv)?);
            i += 2 + end + 1;
            continue;
        }
        // Advance by one *character*, not one byte - `source` is
        // arbitrary user YAML text and may contain multi-byte UTF-8.
        let ch = source[i..].chars().next().expect("i < bytes.len()");
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

fn resolve(inner: &str, dotenv: &BTreeMap<String, String>) -> Result<String, String> {
    let (name, default, error_message) = if let Some(idx) = inner.find(":-") {
        (&inner[..idx], Some(&inner[idx + 2..]), None)
    } else if let Some(idx) = inner.find(":?") {
        (&inner[..idx], None, Some(&inner[idx + 2..]))
    } else {
        (inner, None, None)
    };

    if name.is_empty() {
        return Err(format!("empty variable name in \"${{{inner}}}\""));
    }

    let value = std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| dotenv.get(name).cloned().filter(|v| !v.is_empty()));

    match value {
        Some(v) => Ok(v),
        None => match (default, error_message) {
            (Some(default), _) => Ok(default.to_string()),
            (None, Some(message)) => Err(format!("{name}: {message}")),
            (None, None) => Ok(String::new()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every variable name below is deliberately distinctive
    // (`KILN_COMPOSE_DOTENV_TEST_*`) and never set via `std::env::set_var`
    // by these tests - real process environment variables are shared,
    // mutable global state across a whole test binary, so exercising the
    // "shell env wins" precedence rule here would risk flaking against
    // whatever else runs in the same process. That specific rule is
    // instead checked by `tests/dotenv.rs`'s real subprocess test, where
    // each `Command` gets its own clean, isolated environment.

    #[test]
    fn load_parses_key_value_lines_and_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "FOO=bar\n# a comment\n\nBAZ = qux \n").unwrap();
        let map = load(dir.path());
        assert_eq!(map.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(map.get("BAZ").map(String::as_str), Some("qux"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn load_returns_empty_map_when_dotenv_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_empty());
    }

    #[test]
    fn interpolate_substitutes_a_bare_variable_from_dotenv() {
        let mut dotenv = BTreeMap::new();
        dotenv.insert("KILN_COMPOSE_DOTENV_TEST_BARE".to_string(), "hello".to_string());
        let out = interpolate("image: busybox:${KILN_COMPOSE_DOTENV_TEST_BARE}", &dotenv).unwrap();
        assert_eq!(out, "image: busybox:hello");
    }

    #[test]
    fn interpolate_resolves_an_unset_bare_variable_to_an_empty_string() {
        let dotenv = BTreeMap::new();
        let out = interpolate("[${KILN_COMPOSE_DOTENV_TEST_UNSET_BARE}]", &dotenv).unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn interpolate_uses_the_default_only_when_unset() {
        let mut dotenv = BTreeMap::new();
        dotenv.insert("KILN_COMPOSE_DOTENV_TEST_SET".to_string(), "actual".to_string());
        let out = interpolate(
            "${KILN_COMPOSE_DOTENV_TEST_SET:-fallback} ${KILN_COMPOSE_DOTENV_TEST_UNSET_DEFAULT:-fallback}",
            &dotenv,
        )
        .unwrap();
        assert_eq!(out, "actual fallback");
    }

    #[test]
    fn interpolate_errors_with_the_given_message_when_required_and_unset() {
        let dotenv = BTreeMap::new();
        let err = interpolate("${KILN_COMPOSE_DOTENV_TEST_REQUIRED:?must be set}", &dotenv).unwrap_err();
        assert!(err.contains("must be set"), "unexpected error: {err:?}");
    }

    #[test]
    fn interpolate_double_dollar_is_a_literal_dollar_not_interpreted() {
        let dotenv = BTreeMap::new();
        let out = interpolate("echo $${HOME}", &dotenv).unwrap();
        assert_eq!(out, "echo ${HOME}");
    }

    #[test]
    fn interpolate_reports_an_unterminated_placeholder() {
        let dotenv = BTreeMap::new();
        assert!(interpolate("${OOPS", &dotenv).is_err());
    }
}
