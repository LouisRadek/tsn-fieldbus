use crate::logging::{DEMO_LOG_COMPONENT, set_log_component};
use common::demo_runtime::{
    DEFAULT_DEMO_BRIDGE, try_set_realtime_priority, vlan_priority_code_point,
};
use common::l2_types::parse_l2_frame;
use log::{info, warn};
use pnet::datalink::{self, Channel};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

pub fn spawn_vlan_packet_monitor(stop_flag: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("demo-vlan-monitor".to_string())
        .spawn(move || {
            set_log_component(DEMO_LOG_COMPONENT);
            if let Err(error) = try_set_realtime_priority(45) {
                warn!("Failed to set real-time priority for VLAN monitor: {error}");
            }

            let interface = match datalink::interfaces()
                .into_iter()
                .find(|interface| interface.name == DEFAULT_DEMO_BRIDGE)
            {
                Some(interface) => interface,
                None => {
                    warn!("Bridge interface {DEFAULT_DEMO_BRIDGE} not available for VLAN monitor");
                    return;
                }
            };

            let (_, mut receiver) = match datalink::channel(&interface, Default::default()) {
                Ok(Channel::Ethernet(transmitter, receiver)) => (transmitter, receiver),
                Ok(_) => {
                    warn!("Unsupported channel type for VLAN monitor");
                    return;
                }
                Err(error) => {
                    warn!("Unable to open VLAN monitor channel: {error}");
                    return;
                }
            };

            let mut pcp_counters: HashMap<u8, u64> = HashMap::new();
            let mut seen_packets = 0u64;

            while !stop_flag.load(Ordering::Relaxed) {
                let frame = match receiver.next() {
                    Ok(frame) => frame,
                    Err(_) => continue,
                };

                if let Ok(parsed) = parse_l2_frame(frame) {
                    let pcp = vlan_priority_code_point(parsed.vlan_id_pcp);
                    let stream_id = parsed.header.stream_id;
                    let vlan_tag = parsed.vlan_id_pcp;
                    *pcp_counters.entry(pcp).or_insert(0) += 1;
                    seen_packets = seen_packets.saturating_add(1);

                    if seen_packets <= 40 {
                        info!(
                            "Packet verify: stream={} pcp={} vlan_tag=0x{:04x}",
                            stream_id, pcp, vlan_tag
                        );
                    }
                }
            }

            info!("VLAN packet verification summary (total packets={seen_packets})");
            for (pcp, count) in pcp_counters {
                info!("VLAN PCP {pcp}: {count} packets");
            }
        })
        .expect("Failed to spawn VLAN monitor thread")
}
