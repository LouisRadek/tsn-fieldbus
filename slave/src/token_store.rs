//! Token store and pre-shared key handling for the slave.
//!
//! This module implements a minimal server-side token issuance and
//! validation mechanism. Tokens are created from cryptographically secure
//! random bytes and a timestamp, then stored as a SHA-256 hash together
//! with an expiry instant. The token store validates incoming tokens by
//! comparing hashes and checking expiry. The expected pre-shared key used
//! to request tokens is parsed from environment configuration.
//!
//! Design notes:
//! - Tokens are opaque strings issued to authenticated clients. The
//!   server stores only a hash to avoid keeping token material in clear text.
//! - Tokens have a TTL and are invalidated after expiry.
//! - Multiple concurrent tokens are supported for the prototype.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::slave_api::StatusCode;
use log::warn;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A 256-bit (32 bytes) pre-shared key used to authenticate token requests.
///
/// The contained value is intentionally opaque; its `Debug` implementation
/// hides the material to avoid accidental disclosure in logs.
#[derive(Clone)]
pub struct PreSharedKey(pub [u8; 32]);

impl PreSharedKey {
    /// Attempt to construct a `PreSharedKey` from a byte slice.
    ///
    /// Returns `None` when the input slice is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Some(Self(key))
    }
}

impl std::fmt::Debug for PreSharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PreSharedKey(***HIDDEN***)")
    }
}

/// Parse a textual representation of the shared key.
///
/// Currently accepts a hex string, optionally prefixed with `0x`.
fn parse_shared_key(shared_key_raw: String) -> Result<PreSharedKey, String> {
    let shared_key_raw = shared_key_raw.trim();

    let shared_key_raw_without_prefix = shared_key_raw.strip_prefix("0x").unwrap_or(shared_key_raw);
    if let Ok(vec) = hex::decode(shared_key_raw_without_prefix) {
        if let Some(shared_key) = PreSharedKey::from_bytes(&vec) {
            Ok(shared_key)
        } else {
            Err("Failed to parse shared key with hex encoding!".into())
        }
    } else {
        Err("Failed to decode shared slave key with hex encoding!".into())
    }
}

#[derive(Clone, Copy)]
struct TokenRecord {
    token_hash: [u8; 32],
    expires_at: Instant,
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[derive(Clone)]
pub struct TokenStore {
    /// Expected pre-shared key used to validate token requests.
    expected_shared_key: PreSharedKey,
    /// Active token hashes and expiry times (in-memory).
    tokens: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
}

impl TokenStore {
    pub fn new(expected_shared_key: PreSharedKey) -> Self {
        Self {
            expected_shared_key,
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to create a TokenStore by reading `SHARED_SLAVE_KEY` from the environment file.
    ///
    /// The environment value is expected to be a 64-character hex string (32 bytes),
    /// e.g. produced by `openssl rand -hex 32`.
    pub fn from_env() -> Result<Self, String> {
        let shared_key_raw =
            std::env::var("SHARED_SLAVE_KEY").map_err(|e| format!("Missing env var: {e}"))?;
        let shared_key = parse_shared_key(shared_key_raw)
            .map_err(|e| format!("Invalid SHARED_SLAVE_KEY: {e}"))?;
        Ok(TokenStore::new(shared_key))
    }

    fn generate_token(&self) -> String {
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let token = URL_SAFE_NO_PAD.encode(random);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_nanos();

        format!("{token}.{timestamp:x}")
    }

    /// Issue a new token when the provided `shared_key` matches the configured
    /// pre-shared key. The returned token is a URL-safe base64 string that
    /// encodes random material and a timestamp. The server records the
    /// token hash and expiry for subsequent validation.
    ///
    /// Returns `Err(StatusCode::ErrAuthFailed)` when the shared key is invalid.
    pub fn issue_token(&self, shared_key: &[u8], ttl: Duration) -> Result<String, StatusCode> {
        if !self.is_shared_key_valid(shared_key) {
            warn!("Token request rejected due to invalid shared key part");
            return Err(StatusCode::ErrAuthFailed);
        }

        let token = self.generate_token();
        let token_hash = hash_token(&token);
        let expires_at = Instant::now() + ttl;

        self.insert_token(TokenRecord {
            token_hash,
            expires_at,
        });

        Ok(token)
    }

    fn is_shared_key_valid(&self, shared_key: &[u8]) -> bool {
        if let Some(key) = PreSharedKey::from_bytes(shared_key) {
            key.0 == self.expected_shared_key.0
        } else {
            false
        }
    }

    /// Validate a presented token string.
    ///
    /// The method returns `true` when a token has previously been issued,
    /// its stored hash matches the presented token's hash, and the token
    /// has not yet expired. Expired tokens are removed from the store.
    pub fn validate_token(&self, token: &str) -> bool {
        let token_hash = hash_token(token);
        let now = Instant::now();

        let mut tokens_guard = match self.tokens.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        self.prune_expired_locked(&mut tokens_guard, now);

        match tokens_guard.get(&token_hash) {
            Some(expires_at) if *expires_at > now => true,
            Some(_) => {
                tokens_guard.remove(&token_hash);
                false
            }
            None => false,
        }
    }

    fn insert_token(&self, record: TokenRecord) {
        let mut tokens_guard = match self.tokens.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let now = Instant::now();
        self.prune_expired_locked(&mut tokens_guard, now);

        tokens_guard.insert(record.token_hash, record.expires_at);
    }

    fn prune_expired_locked(&self, tokens_guard: &mut HashMap<[u8; 32], Instant>, now: Instant) {
        tokens_guard.retain(|_, expires_at| *expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_from_bytes_valid() {
        let bytes = [1u8; 32];
        let key = PreSharedKey::from_bytes(&bytes);
        assert!(key.is_some());
        assert_eq!(key.unwrap().0, bytes);
    }

    #[test]
    fn test_from_bytes_invalid_length_short() {
        let bytes = [1u8; 31];
        let key = PreSharedKey::from_bytes(&bytes);
        assert!(key.is_none());
    }

    #[test]
    fn test_from_bytes_invalid_length_long() {
        let bytes = [1u8; 33];
        let key = PreSharedKey::from_bytes(&bytes);
        assert!(key.is_none());
    }

    #[test]
    fn test_debug_impl_hides_key() {
        let key = PreSharedKey([0u8; 32]);
        let debug_str = format!("{:?}", key);
        assert_eq!(debug_str, "PreSharedKey(***HIDDEN***)");
    }

    fn create_store_with_key(key: [u8; 32]) -> TokenStore {
        TokenStore::new(PreSharedKey(key))
    }

    #[test]
    fn test_issue_and_validate_token() {
        let key = [7u8; 32];
        let store = create_store_with_key(key);

        let token = store
            .issue_token(&key, Duration::from_secs(10))
            .expect("token should be issued");

        assert!(store.validate_token(&token));
    }

    #[test]
    fn test_issue_token_rejects_invalid_key() {
        let key = [1u8; 32];
        let store = create_store_with_key(key);
        let invalid_key = [2u8; 32];

        let result = store.issue_token(&invalid_key, Duration::from_secs(10));
        assert_eq!(result, Err(StatusCode::ErrAuthFailed));
    }

    #[test]
    fn test_token_expiry_invalidates_token() {
        let key = [3u8; 32];
        let store = create_store_with_key(key);

        let token = store
            .issue_token(&key, Duration::from_millis(10))
            .expect("token should be issued");

        thread::sleep(Duration::from_millis(20));
        assert!(!store.validate_token(&token));
    }

    #[test]
    fn test_new_token_keeps_previous_valid() {
        let key = [9u8; 32];
        let store = create_store_with_key(key);

        let token_old = store
            .issue_token(&key, Duration::from_secs(10))
            .expect("token should be issued");
        let token_new = store
            .issue_token(&key, Duration::from_secs(10))
            .expect("token should be issued");

        assert!(store.validate_token(&token_old));
        assert!(store.validate_token(&token_new));
    }
}
