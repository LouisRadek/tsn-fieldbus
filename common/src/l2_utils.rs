use crate::hardware_abstraction::ProcessImageAccess;
use crate::slave_api::{StatusCode, StreamConfig};
use log::debug;
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

    if payload.len() < expected_len {
        return Err(StatusCode::ErrInvalidLen);
    }

    debug!(
        "Received input packet for stream_id {}: {} bytes, content: {:02X?}",
        stream.stream_id,
        payload.len(),
        &payload[..expected_len]
    );

    process_image.write_inputs(&payload[..expected_len], *content)?;

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

pub fn absolute_cycle_jitter_ns(observed_cycle_ns: u64, target_cycle_ns: u64) -> u64 {
    observed_cycle_ns.abs_diff(target_cycle_ns)
}

#[derive(Default)]
pub struct CycleMetrics {
    pub min_ns: Option<u64>,
    pub max_ns: Option<u64>,
    pub total_ns: u128,
    pub samples: u64,
}

impl CycleMetrics {
    pub fn record(&mut self, cycle_ns: u64) {
        self.min_ns = Some(self.min_ns.map_or(cycle_ns, |value| value.min(cycle_ns)));
        self.max_ns = Some(self.max_ns.map_or(cycle_ns, |value| value.max(cycle_ns)));
        self.total_ns = self.total_ns.saturating_add(cycle_ns as u128);
        self.samples = self.samples.saturating_add(1);
    }

    pub fn average_ns(&self) -> Option<u64> {
        if self.samples == 0 {
            return None;
        }
        Some((self.total_ns / self.samples as u128) as u64)
    }

    pub fn values(&self) -> Option<(u64, u64, u64)> {
        Some((self.min_ns?, self.max_ns?, self.average_ns()?))
    }
}
