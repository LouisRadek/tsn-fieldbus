//! L2 handler for the master devices.
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

use common::demo_runtime::vlan_priority_code_point;
use common::hardware_abstraction::ProcessImageAccess;
use common::l2_types::{L2Header, build_l2_frame, parse_l2_frame};
use common::l2_utils::{
    build_frame_payload, cycle_counter, find_interface, gcd_all, handle_input_packet,
    parse_destination_mac, ticks_per_cycle, tolerance_ticks,
};
use common::slave_api::{DeviceState, Direction, StatusCode, StreamConfig};
use common::state_machine::DeviceStateManager;
use common::stream_store::StreamStore;
use log::{debug, error, info, warn};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
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
    device_state_manager: DeviceStateManager,
    process_image: Arc<dyn ProcessImageAccess>,
) -> Result<L2HandlerHandle, StatusCode> {
    let interface = find_interface(interface_name);
    let (transmitter, receiver) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(transmitter, receiver)) => (transmitter, receiver),
        Ok(_) => {
            error!("Unhandled Channel for interface: {}", interface_name);
            return Err(StatusCode::ErrSocketChannel);
        }
        Err(e) => {
            error!("Error creating the channel for interface {interface_name}: {e}");
            return Err(StatusCode::ErrSocketChannel);
        }
    };

    let input_streams = stream_store.get_streams_by_direction(Direction::Input);
    let output_streams = stream_store.get_streams_by_direction(Direction::Output);

    info!(
        "Starting master L2 handler on interface={} input_streams={} output_streams={}",
        interface_name,
        input_streams.len(),
        output_streams.len()
    );

    let receiver_handle = spawn_receiver_thread(
        receiver,
        input_streams,
        device_state_manager.clone(),
        process_image.clone(),
        format!("master-{interface_name}"),
    );
    let sender_handle = spawn_sender_thread(
        transmitter,
        interface,
        output_streams,
        device_state_manager,
        process_image,
        format!("master-{interface_name}"),
    )?;

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
    device_state_manager: DeviceStateManager,
    process_image: Arc<dyn ProcessImageAccess>,
) -> Result<L2HandlerHandle, StatusCode> {
    let input_streams = stream_store.get_streams_by_direction(Direction::Input);
    let output_streams = stream_store.get_streams_by_direction(Direction::Output);

    let receiver_handle = spawn_receiver_thread(
        receiver,
        input_streams,
        device_state_manager.clone(),
        process_image.clone(),
        "master-mock".to_string(),
    );
    let sender_handle = spawn_sender_thread(
        transmitter,
        interface,
        output_streams,
        device_state_manager,
        process_image,
        "master-mock".to_string(),
    )?;

    Ok(L2HandlerHandle {
        sender: sender_handle,
        receiver: receiver_handle,
    })
}

fn spawn_receiver_thread(
    mut receiver: Box<dyn DataLinkReceiver>,
    streams: Vec<StreamConfig>,
    device_state_manager: DeviceStateManager,
    process_image: Arc<dyn ProcessImageAccess>,
    thread_group: String,
) -> JoinHandle<()> {
    let mut stream_map = HashMap::new();
    for stream in streams {
        stream_map.insert(stream.stream_id as u16, stream);
    }

    thread::Builder::new()
        .name(format!("{thread_group}-l2-receiving"))
        .spawn(move || {
        info!(
            "L2 receiver thread started with {} input stream(s); active in SafeOp and Op",
            stream_map.len()
        );

        let mut last_cycle_counter: HashMap<u16, u16> = HashMap::new();

        loop {
            let state = device_state_manager.get_state();
            if state != DeviceState::Op && state != DeviceState::SafeOp {
                info!("L2 receiver thread exiting due to state: {state:?}");
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
                    warn!(
                        "Failed to parse L2 frame: {code:?} (frame_len={} bytes)",
                        frame.len()
                    );
                    continue;
                }
            };

            let stream_id = parsed.header.stream_id;
            let Some(stream) = stream_map.get(&stream_id) else {
                error!("Received L2 frame for unknown stream {stream_id}");
                continue;
            };

            debug!(
                "L2 input stream={stream_id} vlan_tci=0x{:04x} pcp={}",
                parsed.vlan_id_pcp,
                vlan_priority_code_point(parsed.vlan_id_pcp)
            );

            if parsed.header.status != StatusCode::NoError as u8 {
                error!(
                    "Received L2 frame with error status for stream {stream_id}: {:?}",
                    parsed.header.status
                );
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
                    warn!(
                        "Cycle counter mismatch for stream {stream_id}: missed_cycles={missed_cycles}"
                    );
                }
            }
            last_cycle_counter.insert(stream_id, parsed.header.cycle_counter);

            if let Err(code) = handle_input_packet(process_image.as_ref(), stream, parsed.payload) {
                error!("Failed to handle packet for stream {stream_id}: {code:?}");
            }
        }
        info!("L2 receiver thread terminated");
    })
    .expect("Failed to spawn master L2 receiver thread")
}

fn spawn_sender_thread(
    mut transmitter: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
    streams: Vec<StreamConfig>,
    device_state_manager: DeviceStateManager,
    process_image: Arc<dyn ProcessImageAccess>,
    thread_group: String,
) -> Result<JoinHandle<()>, StatusCode> {
    let runtime = Handle::current();
    let source_mac = match interface.mac {
        Some(mac) => mac,
        None => return Err(StatusCode::ErrSocketChannel),
    };
    let cycle_times = streams
        .iter()
        .map(|stream| stream.cycle_time_nano)
        .filter(|value| *value > 0)
        .collect::<Vec<_>>();
    let base_cycle_ns = gcd_all(&cycle_times).max(1);

    let handle = thread::Builder::new()
        .name(format!("{thread_group}-l2-transmitting"))
        .spawn(move || {
        info!(
            "L2 sender thread started with {} output stream(s); active in SafeOp and Op",
            streams.len()
        );
        let mut last_sent: HashMap<u16, Instant> = HashMap::new();

        runtime.block_on(async move {
            let mut interval = time::interval(Duration::from_nanos(base_cycle_ns as u64));
            loop {
                let state = device_state_manager.get_state();
                if state != DeviceState::Op && state != DeviceState::SafeOp {
                    info!("L2 sender thread exiting due to state: {state:?}");
                    break;
                }

                interval.tick().await;

                for stream in &streams {
                    let state = device_state_manager.get_state();
                    if state != DeviceState::Op && state != DeviceState::SafeOp {
                        info!("L2 sender thread exiting inner loop due to state: {state:?}");
                        break;
                    }

                    let cycle_time = stream.cycle_time_nano.max(1);
                    let stream_id = stream.stream_id as u16;
                    let due = last_sent
                        .get(&stream_id)
                        .map(|instant| instant.elapsed().as_nanos() as u64 >= cycle_time as u64)
                        .unwrap_or(true);

                    if !due {
                        continue;
                    }

                    last_sent.insert(stream_id, Instant::now());

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
                    }
                }
            }
        });
        info!("L2 sender thread terminated");
    })
    .map_err(|_| StatusCode::ErrSocketChannel)?;

    Ok(handle)
}
