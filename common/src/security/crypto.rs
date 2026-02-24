//! Shared cryptographic helpers for TSN fieldbus authentication.
//!
//! This module provides keyed hashing helpers based on BLAKE3 in keyed mode.
//! The helpers accept pre-split message parts to avoid unnecessary allocations
//! in hot paths.

use crate::security::auth_footer::AUTH_TAG_SIZE;

/// Calculate a truncated authentication tag over concatenated message parts.
///
/// The function uses BLAKE3 keyed hashing with a 32-byte shared secret.
/// Input parts are hashed in the provided order.
pub fn calculate_hmac(secret: &[u8; 32], parts: &[&[u8]]) -> [u8; AUTH_TAG_SIZE] {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    for part in parts {
        hasher.update(part);
    }

    let full = hasher.finalize();
    let mut truncated = [0u8; AUTH_TAG_SIZE];
    truncated.copy_from_slice(&full.as_bytes()[..AUTH_TAG_SIZE]);
    truncated
}

/// Verify an expected authentication tag for concatenated message parts.
///
/// Returns `true` when the calculated tag matches the `expected_tag`.
/// The comparison uses a constant-time byte accumulation strategy.
pub fn verify_hmac(secret: &[u8; 32], parts: &[&[u8]], expected_tag: &[u8; AUTH_TAG_SIZE]) -> bool {
    let calculated = calculate_hmac(secret, parts);

    let mut diff = 0u8;
    for (left, right) in calculated.iter().zip(expected_tag.iter()) {
        diff |= left ^ right;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculate_hmac_is_stable_for_same_input() {
        let secret = [0x11u8; 32];
        let header = [0x01, 0x02, 0x03];
        let payload = [0xAA, 0xBB, 0xCC];
        let sequence = 42u64.to_be_bytes();

        let first = calculate_hmac(&secret, &[&header, &payload, &sequence]);
        let second = calculate_hmac(&secret, &[&header, &payload, &sequence]);
        assert_eq!(first, second);
    }

    #[test]
    fn calculate_hmac_changes_when_part_changes() {
        let secret = [0x22u8; 32];
        let header = [0x10, 0x20];
        let payload_a = [0x01, 0x02];
        let payload_b = [0x01, 0x03];
        let sequence = 7u64.to_be_bytes();

        let tag_a = calculate_hmac(&secret, &[&header, &payload_a, &sequence]);
        let tag_b = calculate_hmac(&secret, &[&header, &payload_b, &sequence]);
        assert_ne!(tag_a, tag_b);
    }

    #[test]
    fn verify_hmac_accepts_valid_tag() {
        let secret = [0x33u8; 32];
        let header = [0x01, 0x00];
        let payload = [0xAB, 0xCD];
        let sequence = 123u64.to_be_bytes();

        let tag = calculate_hmac(&secret, &[&header, &payload, &sequence]);
        assert!(verify_hmac(&secret, &[&header, &payload, &sequence], &tag));
    }

    #[test]
    fn verify_hmac_rejects_invalid_tag() {
        let secret = [0x44u8; 32];
        let header = [0x01, 0xFF];
        let payload = [0x10, 0x20];
        let sequence = 99u64.to_be_bytes();

        let mut invalid_tag = calculate_hmac(&secret, &[&header, &payload, &sequence]);
        invalid_tag[0] ^= 0x01;

        assert!(!verify_hmac(
            &secret,
            &[&header, &payload, &sequence],
            &invalid_tag
        ));
    }
}
