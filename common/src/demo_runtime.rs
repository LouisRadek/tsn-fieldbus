//! Linux demo runtime utilities for the TSN fieldbus prototype.
//!
//! This module provides helper functions used by the demo runtime:
//! - Setup and teardown of a Linux virtual L2 network using `ip link`
//! - VLAN Tag encoding/decoding helpers for PCP verification
//! - Best-effort real-time scheduling configuration for worker threads

use libc::{SCHED_FIFO, sched_param, sched_setscheduler};
use std::ffi::OsStr;
use std::process::Command;

pub const DEFAULT_DEMO_BRIDGE: &str = "tsn-demo-br0";
pub const DEMO_MASTER_INTERFACE: &str = "tsn-master0";
pub const DEMO_MASTER_BRIDGE_PEER: &str = "tsn-master0-br";
pub const DEMO_TEMPERATURE_INTERFACE: &str = "tsn-s-temp0";
pub const DEMO_TEMPERATURE_BRIDGE_PEER: &str = "tsn-s-temp0-br";
pub const DEMO_VALVE_INTERFACE: &str = "tsn-s-valve0";
pub const DEMO_VALVE_BRIDGE_PEER: &str = "tsn-s-valve0-br";

pub const DEMO_MASTER_IP_CONFIG: &str = "10.10.0.1/24";

pub fn build_vlan_tag(vlan_id: u16, priority_code_point: u8) -> u16 {
    let pcp = (priority_code_point & 0x07) as u16;
    ((pcp << 13) & 0xE000) | (vlan_id & 0x0FFF)
}

pub fn vlan_identifier(vlan_tag: u16) -> u16 {
    vlan_tag & 0x0FFF
}

pub fn setup_demo_network() -> Result<(), String> {
    teardown_demo_network().ok();

    run_ip(["link", "add", "name", DEFAULT_DEMO_BRIDGE, "type", "bridge"])?;
    run_ip(["link", "set", "dev", DEFAULT_DEMO_BRIDGE, "up"])?;

    create_veth_pair(DEMO_MASTER_INTERFACE, DEMO_MASTER_BRIDGE_PEER)?;
    create_veth_pair(DEMO_TEMPERATURE_INTERFACE, DEMO_TEMPERATURE_BRIDGE_PEER)?;
    create_veth_pair(DEMO_VALVE_INTERFACE, DEMO_VALVE_BRIDGE_PEER)?;

    attach_to_bridge(DEMO_MASTER_BRIDGE_PEER, DEFAULT_DEMO_BRIDGE)?;
    attach_to_bridge(DEMO_TEMPERATURE_BRIDGE_PEER, DEFAULT_DEMO_BRIDGE)?;
    attach_to_bridge(DEMO_VALVE_BRIDGE_PEER, DEFAULT_DEMO_BRIDGE)?;

    run_ip(["addr", "flush", "dev", DEMO_MASTER_INTERFACE])?;
    run_ip([
        "addr",
        "add",
        DEMO_MASTER_IP_CONFIG,
        "dev",
        DEMO_MASTER_INTERFACE,
    ])?;
    run_ip(["link", "set", "dev", DEMO_MASTER_INTERFACE, "up"])?;

    Ok(())
}

pub fn teardown_demo_network() -> Result<(), String> {
    for interface in [
        DEMO_MASTER_INTERFACE,
        DEMO_MASTER_BRIDGE_PEER,
        DEMO_TEMPERATURE_INTERFACE,
        DEMO_TEMPERATURE_BRIDGE_PEER,
        DEMO_VALVE_INTERFACE,
        DEMO_VALVE_BRIDGE_PEER,
    ] {
        run_ip_allow_fail(["link", "del", "dev", interface]);
    }

    run_ip_allow_fail(["link", "set", "dev", DEFAULT_DEMO_BRIDGE, "down"]);
    run_ip_allow_fail(["link", "del", "name", DEFAULT_DEMO_BRIDGE, "type", "bridge"]);

    Ok(())
}

pub fn configure_interface_ipv4(
    interface_name: &str,
    ip: [u8; 4],
    netmask: [u8; 4],
) -> Result<(), String> {
    let prefix = netmask_to_prefix_length(netmask)?;
    let ip_config = format!("{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], prefix);

    run_ip(["addr", "flush", "dev", interface_name])?;
    run_ip(["addr", "add", ip_config.as_str(), "dev", interface_name])?;
    run_ip(["link", "set", "dev", interface_name, "up"])?;

    Ok(())
}

pub fn try_set_realtime_priority(priority: i32) -> Result<(), String> {
    let parameter = sched_param {
        sched_priority: priority,
    };

    let result = unsafe { sched_setscheduler(0, SCHED_FIFO, &parameter) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

fn create_veth_pair(endpoint: &str, bridge_peer: &str) -> Result<(), String> {
    run_ip([
        "link",
        "add",
        "name",
        endpoint,
        "type",
        "veth",
        "peer",
        "name",
        bridge_peer,
    ])?;
    run_ip(["link", "set", "dev", endpoint, "up"])?;
    run_ip(["link", "set", "dev", bridge_peer, "up"])?;
    Ok(())
}

fn attach_to_bridge(interface_name: &str, bridge_name: &str) -> Result<(), String> {
    run_ip(["link", "set", "dev", interface_name, "master", bridge_name])?;
    run_ip(["link", "set", "dev", interface_name, "up"])?;
    Ok(())
}

fn netmask_to_prefix_length(netmask: [u8; 4]) -> Result<u8, String> {
    let mut prefix = 0u8;
    let mut hit_zero = false;
    for octet in netmask {
        for index in (0..8).rev() {
            let bit_set = ((octet >> index) & 1) == 1;
            if bit_set {
                if hit_zero {
                    return Err("Invalid non-contiguous netmask".to_string());
                }
                prefix = prefix.saturating_add(1);
            } else {
                hit_zero = true;
            }
        }
    }

    Ok(prefix)
}

fn run_ip<const N: usize>(arguments: [&str; N]) -> Result<(), String> {
    let output = Command::new(OsStr::new("ip"))
        .args(arguments)
        .output()
        .map_err(|error| format!("Failed to run ip command: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(format!(
        "ip command failed: ip {}: {}",
        arguments.join(" "),
        stderr
    ))
}

fn run_ip_allow_fail<const N: usize>(arguments: [&str; N]) {
    let _ = Command::new(OsStr::new("ip")).args(arguments).output();
}
