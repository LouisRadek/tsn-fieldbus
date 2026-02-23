//! Security footer types for authenticated SDCP and L2 frames.

use crate::slave_api::StatusCode;

pub const AUTH_TAG_SIZE: usize = 32;
pub const SECURITY_FOOTER_SIZE: usize = 8 + AUTH_TAG_SIZE;

/// Authentication footer appended to protocol payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityFooter {
    pub sequence_number: u64,
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

impl SecurityFooter {
    /// Serialize the footer in network byte order.
    pub fn write_to(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.sequence_number.to_be_bytes());
        output.extend_from_slice(&self.auth_tag);
    }

    /// Parse a footer from an exact 40-byte input slice.
    pub fn read_from(input: &[u8]) -> Result<Self, StatusCode> {
        if input.len() != SECURITY_FOOTER_SIZE {
            return Err(StatusCode::ErrInvalidLen);
        }

        let mut sequence_bytes = [0u8; 8];
        sequence_bytes.copy_from_slice(&input[..8]);

        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        auth_tag.copy_from_slice(&input[8..8 + AUTH_TAG_SIZE]);

        Ok(Self {
            sequence_number: u64::from_be_bytes(sequence_bytes),
            auth_tag,
        })
    }
}

/// Split a payload into application data and security footer.
pub fn split_payload_and_footer(payload: &[u8]) -> Result<(&[u8], SecurityFooter), StatusCode> {
    if payload.len() < SECURITY_FOOTER_SIZE {
        return Err(StatusCode::ErrInvalidLen);
    }

    let footer_start = payload.len() - SECURITY_FOOTER_SIZE;
    let footer = SecurityFooter::read_from(&payload[footer_start..])?;
    Ok((&payload[..footer_start], footer))
}
