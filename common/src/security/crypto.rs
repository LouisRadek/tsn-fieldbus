//! Shared cryptographic helpers for TSN fieldbus authentication.
//!
//! This module provides keyed hashing helpers based on BLAKE3 in keyed mode.
//! The helpers accept pre-split message parts to avoid unnecessary allocations
//! in hot paths.

/// Calculate a 32-byte authentication tag over concatenated message parts.
///
/// The function uses BLAKE3 keyed hashing with a 32-byte shared secret.
/// Input parts are hashed in the provided order.
pub fn calculate_hmac(secret: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    for part in parts {
        hasher.update(part);
    }

    *hasher.finalize().as_bytes()
}

/// Verify an expected authentication tag for concatenated message parts.
///
/// Returns `true` when the calculated tag matches the `expected_tag`.
/// The comparison uses a constant-time byte accumulation strategy.
pub fn verify_hmac(secret: &[u8; 32], parts: &[&[u8]], expected_tag: &[u8; 32]) -> bool {
    let calculated = calculate_hmac(secret, parts);

    let mut diff = 0u8;
    for (left, right) in calculated.iter().zip(expected_tag.iter()) {
        diff |= left ^ right;
    }

    diff == 0
}
