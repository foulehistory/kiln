//! Password hashing and the in-memory Bearer token store.
//!
//! No JWT/crypto-token-format dependency: a token is just 32 random
//! bytes the server remembers the meaning of (repository + granted
//! actions + expiry) in a `HashMap` - correct and sufficient for a
//! single-process server, and consistent with this workspace's general
//! preference for hand-rolled-and-simple over pulling in a framework
//! (see `kilnd-core::http`'s own module docs for the same reasoning
//! applied to the HTTP layer itself).

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("hashing a password cannot fail")
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else { return false };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

struct Claims {
    repository: String,
    actions: Vec<String>,
    expires_at: SystemTime,
}

const TOKEN_TTL: Duration = Duration::from_secs(3600);

pub struct TokenStore {
    tokens: Mutex<HashMap<String, Claims>>,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    pub fn new() -> Self {
        TokenStore {
            tokens: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, repository: String, actions: Vec<String>) -> String {
        let token = random_token();
        let claims = Claims {
            repository,
            actions,
            expires_at: SystemTime::now() + TOKEN_TTL,
        };
        self.tokens.lock().expect("token store mutex poisoned").insert(token.clone(), claims);
        token
    }

    /// `true` iff `token` is known, unexpired, and was granted `action`
    /// for exactly `repository`.
    pub fn validate(&self, token: &str, repository: &str, action: &str) -> bool {
        let tokens = self.tokens.lock().expect("token store mutex poisoned");
        match tokens.get(token) {
            Some(claims) => claims.repository == repository && claims.actions.iter().any(|a| a == action) && claims.expires_at > SystemTime::now(),
            None => false,
        }
    }

    /// Same as [`Self::validate`], but for `GET /users/:username/pubkey` -
    /// an endpoint keyed by account name rather than an exact repository,
    /// so it accepts any unexpired token granted `action` for *some*
    /// repository under `owner`'s own namespace (i.e. whose first path
    /// segment is `owner`). This is what lets the existing pull client
    /// (`kiln_image::registry::verify_signature`, which already reuses
    /// its one repository-scoped pull token as the Bearer header for the
    /// pubkey fetch too) keep working unmodified now that this endpoint
    /// requires a token at all.
    pub fn validate_for_owner(&self, token: &str, owner: &str, action: &str) -> bool {
        let tokens = self.tokens.lock().expect("token store mutex poisoned");
        match tokens.get(token) {
            Some(claims) => {
                claims.repository.split('/').next() == Some(owner)
                    && claims.actions.iter().any(|a| a == action)
                    && claims.expires_at > SystemTime::now()
            }
            None => false,
        }
    }
}
