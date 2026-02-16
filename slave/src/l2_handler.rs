//! L2 handler for slave devices.
//!
//! The L2 handler spawns two long-lived threads:
//! - A receiver thread that continuously reads raw Ethernet frames and
//!   validates them before writing input data into the process image.
//! - A sender thread that uses a Tokio interval to transmit cyclic output
//!   frames according to the configured stream cycle times.
//!
//! # Validation Rules
//!
//! Incoming L2 frames are validated in the following order:
//! - L2 parsing succeeds and the stream ID is known.
//! - The header status is `NoError`.
//! - The cycle counter matches the expected value within a tolerance window
//!   derived from the configured cycle time. The tolerance is expressed in
//!   ticks to account for jitter and counter wrap-around.

use crate::DeviceStatusStore;
use common::demo_runtime::vlan_priority_code_point;
use common::hardware_abstraction::ProcessImageAccess;
use common::l2_types::{L2Header, build_l2_frame, parse_l2_frame};
use common::l2_utils::{
    build_frame_payload, cycle_counter, find_interface, gcd_all, handle_input_packet,
    parse_destination_mac, ticks_per_cycle, tolerance_ticks,
};
use common::slave_api::{DeviceState, Direction, StatusCode, StreamConfig};
use common::stream_store::StreamStore;
use log::{debug, error, info, warn};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::time;

pub struct L2HandlerHandle {
    sender: JoinHandle<()>,
    receiver: JoinHandle<()>,
}

impl L2HandlerHandle {
    pub fn join(self) {
        let _ = self.sender.join();
        let _ = self.receiver.join();
    }
}

pub fn start_l2_handler(
    interface_name: &str,
    stream_store: StreamStore,
    status_store: DeviceStatusStore,
    process_image: Arc<dyn ProcessImageAccess>,
) -> Result<L2HandlerHandle, StatusCode> {
    let interface = find_interface(interface_name);
    let (transmitter, receiver) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(transmitter, receiver)) => (transmitter, receiver),
        Ok(_) => {
            error!("Unhandled channel type for interface: {}", interface.name);
            return Err(StatusCode::ErrSocketChannel);
        }
        Err(e) => {
            error!("Failed to create datalink channel: {e}");
            return Err(StatusCode::ErrSocketChannel);
        }
    };

    let input_streams = stream_store.get_streams_by_direction(Direction::Input);
    let output_streams = stream_store.get_streams_by_direction(Direction::Output);

    info!(
        "Starting slave L2 handler on interface={} input_streams={} output_streams={}",
        interface_name,
        input_streams.len(),
        output_streams.len()
    );

    let receiver_handle = spawn_receiver_thread(
        receiver,
        input_streams,
        status_store.clone(),
        process_image.clone(),
        format!("slave-{interface_name}"),
    );
    let sender_handle = spawn_sender_thread(
        transmitter,
        interface,
        output_streams,
        status_store,
        process_image,
        format!("slave-{interface_name}"),
    );

    Ok(L2HandlerHandle {
        sender: sender_handle,
        receiver: receiver_handle,
    })
}

#[cfg(feature = "test-utils")]
pub fn start_l2_handler_with_mocks(
    interface: NetworkInterface,
    transmitter: Box<dyn DataLinkSender>,
    receiver: Box<dyn DataLinkReceiver>,
    stream_store: StreamStore,
    status_store: DeviceStatusStore,
    process_image: Arc<dyn ProcessImageAccess>,
) -> L2HandlerHandle {
    let input_streams = stream_store.get_streams_by_direction(Direction::Input);
    let output_streams = stream_store.get_streams_by_direction(Direction::Output);

    let receiver_handle = spawn_receiver_thread(
        receiver,
        input_streams,
        status_store.clone(),
        process_image.clone(),
        "slave-mock".to_string(),
    );
    let sender_handle = spawn_sender_thread(
        transmitter,
        interface,
        output_streams,
        status_store,
        process_image,
        "slave-mock".to_string(),
    );

    L2HandlerHandle {
        sender: sender_handle,
        receiver: receiver_handle,
    }
}

fn spawn_receiver_thread(
    mut receiver: Box<dyn DataLinkReceiver>,
    streams: Vec<StreamConfig>,
    status_store: DeviceStatusStore,
    process_image: Arc<dyn ProcessImageAccess>,
    thread_group: String,
) -> JoinHandle<()> {
    let runtime = Handle::current();
    let mut stream_map = HashMap::new();
    for stream in streams {
        stream_map.insert(stream.stream_id as u16, stream);
    }

    thread::Builder::new()
        .name(format!("{thread_group}-l2-receiving"))
        .spawn(move || {
        info!(
            "Slave L2 receiver thread started with {} input stream(s); active in Op",
            stream_map.len()
        );
        
        let mut last_cycle_counter: HashMap<u16, u16> = HashMap::new();

        loop {
            let status = runtime.block_on(status_store.get_status());
            let state = DeviceState::try_from(status.state).unwrap_or(DeviceState::Init);
            if state == DeviceState::SafeOp {
                thread::sleep(Duration::from_micros(500));
                continue;
            } else if state != DeviceState::Op {
                info!("Slave L2 receiver thread exiting due to state: {state:?}");
                break;
            }

            let frame = match receiver.next() {
                Ok(frame) => frame,
                Err(e) => {
                    error!("Receiver error: {e}");
                    continue;
                }
            };

            let parsed = match parse_l2_frame(frame) {
                Ok(parsed) => parsed,
                Err(StatusCode::ErrInvalidEthertype) => {
                    continue;
                }
                Err(code) => {
                    warn!("Failed to parse L2 frame: {code:?}");
                    runtime.block_on(status_store.update_status_code(StatusCode::ErrFrameParsing));
                    continue;
                }
            };

            let stream_id = parsed.header.stream_id;
            let Some(stream) = stream_map.get(&stream_id) else {
                warn!("Received L2 frame for unknown stream {stream_id}");
                runtime.block_on(status_store.update_status_code(StatusCode::ErrStreamIdUnknown));
                continue;
            };

            debug!(
                "L2 input stream={stream_id} vlan_tci=0x{:04x} pcp={}",
                parsed.vlan_id_pcp,
                vlan_priority_code_point(parsed.vlan_id_pcp)
            );

            if parsed.header.status != StatusCode::NoError as u8 {
                warn!(
                    "Received L2 frame with error status for stream {stream_id}: {:?}",
                    parsed.header.status
                );
                runtime
                    .block_on(status_store.update_status_code(StatusCode::ErrFrameWithErrorStatus));
                continue;
            }

            if let Some(last) = last_cycle_counter.get(&stream_id) {
                let ticks = ticks_per_cycle(stream.cycle_time_nano);
                let expected = last.wrapping_add(ticks as u16);
                let received = parsed.header.cycle_counter;
                let forward = received.wrapping_sub(expected) as u32;
                let backward = expected.wrapping_sub(received) as u32;
                let tolerance = tolerance_ticks(stream.cycle_time_nano);

                if forward.min(backward) > tolerance {
                    let missed_cycles = if forward <= backward {
                        forward.div_ceil(ticks)
                    } else {
                        1
                    };
                    runtime.block_on(status_store.increment_missed_cycles_by(missed_cycles));
                    runtime.block_on(status_store.update_status_code(StatusCode::ErrCycleCounter));
                }
            }
            last_cycle_counter.insert(stream_id, parsed.header.cycle_counter);

            if let Err(code) = handle_input_packet(process_image.as_ref(), stream, parsed.payload) {
                runtime.block_on(status_store.update_status_code(code));
            }
        }
        info!("Slave L2 receiver thread terminated");
    })
    .expect("Failed to spawn slave L2 receiver thread")
}

fn spawn_sender_thread(
    mut transmitter: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
    streams: Vec<StreamConfig>,
    status_store: DeviceStatusStore,
    process_image: Arc<dyn ProcessImageAccess>,
    thread_group: String,
) -> JoinHandle<()> {
    let runtime = tokio::runtime::Handle::current();
    let source_mac = interface.mac.unwrap_or(MacAddr::zero());
    let cycle_times = streams
        .iter()
        .map(|stream| stream.cycle_time_nano)
        .filter(|value| *value > 0)
        .collect::<Vec<_>>();
    let base_cycle = gcd_all(&cycle_times).max(1);

    thread::Builder::new()
        .name(format!("{thread_group}-l2-transmitting"))
        .spawn(move || {
        info!(
            "L2 sender thread started with {} output stream(s); active in SafeOp and Op",
            streams.len()
        );
        let mut last_sent: HashMap<u16, Instant> = HashMap::new();
        let mut min_cycle = u32::MAX;
        let mut max_cycle = 0u32;

        runtime.block_on(async move {
            let mut interval = time::interval(Duration::from_nanos(base_cycle as u64));
            loop {
                interval.tick().await;

                let status = status_store.get_status().await;
                let state = DeviceState::try_from(status.state).unwrap_or(DeviceState::Init);
                if state != DeviceState::Op && state != DeviceState::SafeOp {
                    info!("Slave L2 sender thread exiting due to state: {state:?}");
                    break;
                }

                for stream in &streams {
                    let cycle_time = stream.cycle_time_nano.max(1);
                    let stream_id = stream.stream_id as u16;
                    let due = last_sent
                        .get(&stream_id)
                        .map(|instant| instant.elapsed().as_nanos() as u64 >= cycle_time as u64)
                        .unwrap_or(true);

                    if !due {
                        continue;
                    }

                    let now = Instant::now();
                    if let Some(previous) = last_sent.insert(stream_id, now) {
                        let elapsed = now.duration_since(previous);
                        let elapsed_ns = elapsed.as_nanos() as u32;
                        min_cycle = min_cycle.min(elapsed_ns);
                        max_cycle = max_cycle.max(elapsed_ns);
                        status_store.update_min_cycle_time(min_cycle).await;
                        status_store.update_max_cycle_time(max_cycle).await;
                    }

                    let mut status = StatusCode::NoError;
                    let payload = match build_frame_payload(process_image.as_ref(), stream) {
                        Ok(payload) => payload,
                        Err(code) => {
                            error!("Failed to package data for stream {stream_id}: {code:?}");
                            status = code;
                            Vec::<u8>::new()
                        }
                    };

                    let destination = parse_destination_mac(stream);
                    let header =
                        L2Header::new(stream.stream_id as u16, cycle_counter(), status as u8);
                    let frame = build_l2_frame(
                        source_mac,
                        destination,
                        stream.vlan_id_pcp as u16,
                        &header,
                        &payload,
                    );

                    debug!(
                        "L2 output stream={} vlan_tci=0x{:04x} pcp={}",
                        stream.stream_id,
                        stream.vlan_id_pcp as u16,
                        vlan_priority_code_point(stream.vlan_id_pcp as u16)
                    );

                    if let Some(Err(error)) = transmitter.send_to(&frame, None) {
                        error!("Failed to send L2 frame for stream {stream_id}: {error}");
                        status_store
                            .update_status_code(StatusCode::ErrSocketChannel)
                            .await;
                    }
                }
            }
        });
        info!("Slave L2 sender thread terminated");
    })
    .expect("Failed to spawn slave L2 sender thread")
}
