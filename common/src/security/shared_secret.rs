//! Shared secret loading helpers.
//!
//! This module centralizes parsing of the prototype's shared secret from
//! environment configuration.

/// Environment variable used to configure the 32-byte shared secret.
pub const SHARED_SECRET_ENV_VAR: &str = "SHARED_SLAVE_KEY";

/// Load the shared secret from the environment.
///
/// The value is expected as a hexadecimal string representing 32 bytes.
/// A leading `0x` prefix is accepted.
pub fn load_shared_secret_from_env() -> Result<[u8; 32], String> {
    let _ = dotenvy::dotenv();

    let raw_secret = std::env::var(SHARED_SECRET_ENV_VAR)
        .map_err(|error| {
            format!(
                "Missing env var {SHARED_SECRET_ENV_VAR}: {error}. Ensure it is exported or present in a .env file."
            )
        })?;

    parse_shared_secret_hex(&raw_secret)
}

pub fn parse_shared_secret_hex(raw_secret: &str) -> Result<[u8; 32], String> {
    let trimmed_secret = raw_secret.trim();
    let without_prefix = trimmed_secret.strip_prefix("0x").unwrap_or(trimmed_secret);

    let decoded = hex::decode(without_prefix)
        .map_err(|error| format!("Invalid shared secret hex: {error}"))?;

    if decoded.len() != 32 {
        return Err("Shared secret must decode to exactly 32 bytes".to_string());
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&decoded);
    Ok(secret)
}
