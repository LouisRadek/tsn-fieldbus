use crate::hardware_abstraction::ProcessImageAccess;
use crate::slave_api::{StatusCode, StreamConfig};
use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CYCLE_COUNTER_TICK_NS: u64 = 31_250;
pub const ALLOWED_MULTIPLE_OVER_CYCLE_TIME: f32 = 1.5;

pub fn find_interface(interface_name: &str) -> NetworkInterface {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|interface| interface.name == interface_name)
        .expect("Could not find network interface")
}

pub fn handle_input_packet(
    process_image: &dyn ProcessImageAccess,
    stream: &StreamConfig,
    payload: &[u8],
) -> Result<(), StatusCode> {
    let content = stream
        .stream_content
        .as_ref()
        .ok_or(StatusCode::ErrParamInvalid)?;
    let expected_len = bit_len_to_byte_len(content.bit_len);

    if payload.len() != expected_len {
        return Err(StatusCode::ErrInvalidLen);
    }

    process_image.write_inputs(payload, *content)?;

    Ok(())
}

pub fn build_frame_payload(
    process_image: &dyn ProcessImageAccess,
    stream: &StreamConfig,
) -> Result<Vec<u8>, StatusCode> {
    let content = stream
        .stream_content
        .as_ref()
        .ok_or(StatusCode::ErrParamInvalid)?;

    process_image.read_outputs(*content)
}

pub fn bit_len_to_byte_len(bit_len: u32) -> usize {
    bit_len.div_ceil(8) as usize
}

pub fn gcd_u32(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let tmp = a % b;
        a = b;
        b = tmp;
    }
    a
}

pub fn gcd_all(values: &[u32]) -> u32 {
    let mut iter = values.iter().copied();
    let Some(mut acc) = iter.next() else {
        return 0;
    };
    for value in iter {
        acc = gcd_u32(acc, value);
    }
    acc
}

pub fn cycle_counter() -> u16 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_micros = since_epoch.as_micros();
    let ticks = (total_micros * 4) / 125;
    (ticks % 0xFFFF) as u16
}

pub fn ticks_per_cycle(cycle_time_nano: u32) -> u32 {
    let cycle_ns = cycle_time_nano.max(1) as u64;
    let ticks = cycle_ns.div_ceil(CYCLE_COUNTER_TICK_NS);
    ticks.max(1) as u32
}

pub fn tolerance_ticks(cycle_time_nano: u32) -> u32 {
    let cycle_ns = cycle_time_nano.max(1) as f64;
    let tolerance_ns = cycle_ns * ALLOWED_MULTIPLE_OVER_CYCLE_TIME as f64;
    let ticks = (tolerance_ns / CYCLE_COUNTER_TICK_NS as f64).ceil() as u32;
    ticks.max(1)
}

pub fn parse_destination_mac(stream: &StreamConfig) -> MacAddr {
    MacAddr::new(
        stream.destination_mac[0],
        stream.destination_mac[1],
        stream.destination_mac[2],
        stream.destination_mac[3],
        stream.destination_mac[4],
        stream.destination_mac[5],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_len_to_byte_len_rounds_up() {
        assert_eq!(bit_len_to_byte_len(0), 0);
        assert_eq!(bit_len_to_byte_len(1), 1);
        assert_eq!(bit_len_to_byte_len(7), 1);
        assert_eq!(bit_len_to_byte_len(8), 1);
        assert_eq!(bit_len_to_byte_len(9), 2);
        assert_eq!(bit_len_to_byte_len(16), 2);
    }

    #[test]
    fn gcd_all_returns_zero_for_empty_slice() {
        let values: [u32; 0] = [];
        assert_eq!(gcd_all(&values), 0);
    }

    #[test]
    fn gcd_all_reduces_values() {
        assert_eq!(gcd_all(&[12, 18, 24]), 6);
        assert_eq!(gcd_all(&[7, 11]), 1);
    }

    #[test]
    fn ticks_per_cycle_ceil_and_minimum() {
        assert_eq!(ticks_per_cycle(1), 1);
        assert_eq!(ticks_per_cycle(CYCLE_COUNTER_TICK_NS as u32), 1);
        assert_eq!(ticks_per_cycle((CYCLE_COUNTER_TICK_NS + 1) as u32), 2);
    }

    #[test]
    fn tolerance_ticks_matches_multiplier() {
        let cycle_ns = CYCLE_COUNTER_TICK_NS as u32 * 4;
        let expected = ((cycle_ns as f64 * ALLOWED_MULTIPLE_OVER_CYCLE_TIME as f64)
            / CYCLE_COUNTER_TICK_NS as f64)
            .ceil() as u32;
        assert_eq!(tolerance_ticks(cycle_ns), expected.max(1));
    }
}
