use crate::logging::{DEMO_LOG_COMPONENT, MASTER_LOG_COMPONENT};
use log::info;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const POST_RUN_SUMMARY_FILE: &str = "post_run_summary.txt";

#[derive(Default)]
struct DevicePerformance {
    first_seen_state_timestamps: HashMap<i32, u64>,
    last_status_code: i32,
    last_missed_cycles: u32,
    min_cycle_time_ns: Option<u32>,
    max_cycle_time_ns: Option<u32>,
}

impl DevicePerformance {
    fn update(
        &mut self,
        timestamp_ms: u64,
        state: i32,
        status_code: i32,
        missed_cycles: u32,
        min_cycle_time_ns: u32,
        max_cycle_time_ns: u32,
    ) {
        self.first_seen_state_timestamps
            .entry(state)
            .or_insert(timestamp_ms);
        self.last_status_code = status_code;
        self.last_missed_cycles = missed_cycles;

        if min_cycle_time_ns > 0 {
            self.min_cycle_time_ns = Some(
                self.min_cycle_time_ns
                    .map(|value| value.min(min_cycle_time_ns))
                    .unwrap_or(min_cycle_time_ns),
            );
        }

        if max_cycle_time_ns > 0 {
            self.max_cycle_time_ns = Some(
                self.max_cycle_time_ns
                    .map(|value| value.max(max_cycle_time_ns))
                    .unwrap_or(max_cycle_time_ns),
            );
        }
    }

    fn state_latency_ms(&self, from_state: i32, to_state: i32) -> Option<u64> {
        let start = self.first_seen_state_timestamps.get(&from_state)?;
        let end = self.first_seen_state_timestamps.get(&to_state)?;
        Some(end.saturating_sub(*start))
    }
}

fn parse_log_timestamp_ms(line: &str) -> Option<u64> {
    let timestamp = line.split_once(' ')?.0;
    timestamp.parse::<u64>().ok()
}

fn parse_numeric_field(line: &str, field_name: &str) -> Option<i64> {
    let key = format!("{field_name}=");
    line.split_whitespace().find_map(|token| {
        token
            .trim_end_matches(',')
            .strip_prefix(&key)
            .and_then(|value| value.parse::<i64>().ok())
    })
}

fn parse_bool_field(line: &str, field_name: &str) -> Option<bool> {
    let key = format!("{field_name}=");
    line.split_whitespace().find_map(|token| {
        token
            .trim_end_matches(',')
            .strip_prefix(&key)
            .and_then(|value| match value {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            })
    })
}

fn state_name(state: i32) -> &'static str {
    match state {
        0 => "Init",
        1 => "DiscoverySync",
        2 => "PreOp",
        3 => "SafeOp",
        4 => "Op",
        5 => "Error",
        6 => "Shutdown",
        _ => "Unknown",
    }
}

fn render_device_performance_summary(
    device_name: &str,
    metrics: &DevicePerformance,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("{device_name}:"));
    lines.push(format!(
        "  last_status_code={} last_missed_cycles={}",
        metrics.last_status_code, metrics.last_missed_cycles
    ));

    for (from_state, to_state) in [(2, 3), (3, 4), (4, 6)] {
        if let Some(latency) = metrics.state_latency_ms(from_state, to_state) {
            lines.push(format!(
                "  state_latency_{}_to_{}={}ms",
                state_name(from_state),
                state_name(to_state),
                latency
            ));
        }
    }

    if let Some(min_cycle_time_ns) = metrics.min_cycle_time_ns {
        lines.push(format!("  min_cycle_time_ns={min_cycle_time_ns}"));
    }
    if let Some(max_cycle_time_ns) = metrics.max_cycle_time_ns {
        lines.push(format!("  max_cycle_time_ns={max_cycle_time_ns}"));
    }

    lines
}

pub fn run_post_run_log_analysis(log_directory: &Path) -> Result<(), String> {
    let master_log_path = log_directory.join(format!("{MASTER_LOG_COMPONENT}.log"));
    let demo_log_path = log_directory.join(format!("{DEMO_LOG_COMPONENT}.log"));

    let master_content = fs::read_to_string(&master_log_path)
        .map_err(|error| format!("Failed to read {}: {error}", master_log_path.display()))?;
    let demo_content = fs::read_to_string(&demo_log_path)
        .map_err(|error| format!("Failed to read {}: {error}", demo_log_path.display()))?;

    let mut temperature_metrics = DevicePerformance::default();
    let mut valve_metrics = DevicePerformance::default();

    let mut control_iterations = 0u64;
    let mut valve_open_iterations = 0u64;
    let mut max_temperature = 0u16;

    for line in master_content.lines() {
        let Some(timestamp_ms) = parse_log_timestamp_ms(line) else {
            continue;
        };

        if line.contains("Temperature status update:") {
            let state = parse_numeric_field(line, "state").unwrap_or_default() as i32;
            let status_code = parse_numeric_field(line, "status_code").unwrap_or_default() as i32;
            let missed_cycles =
                parse_numeric_field(line, "missed_cycles").unwrap_or_default() as u32;
            let min_cycle_time_ns =
                parse_numeric_field(line, "min_cycle_time_ns").unwrap_or_default() as u32;
            let max_cycle_time_ns =
                parse_numeric_field(line, "max_cycle_time_ns").unwrap_or_default() as u32;
            temperature_metrics.update(
                timestamp_ms,
                state,
                status_code,
                missed_cycles,
                min_cycle_time_ns,
                max_cycle_time_ns,
            );
            continue;
        }

        if line.contains("Valve status update:") {
            let state = parse_numeric_field(line, "state").unwrap_or_default() as i32;
            let status_code = parse_numeric_field(line, "status_code").unwrap_or_default() as i32;
            let missed_cycles =
                parse_numeric_field(line, "missed_cycles").unwrap_or_default() as u32;
            let min_cycle_time_ns =
                parse_numeric_field(line, "min_cycle_time_ns").unwrap_or_default() as u32;
            let max_cycle_time_ns =
                parse_numeric_field(line, "max_cycle_time_ns").unwrap_or_default() as u32;
            valve_metrics.update(
                timestamp_ms,
                state,
                status_code,
                missed_cycles,
                min_cycle_time_ns,
                max_cycle_time_ns,
            );
            continue;
        }

        if line.contains("Control loop:") {
            control_iterations = control_iterations.saturating_add(1);
            let temperature = parse_numeric_field(line, "temperature").unwrap_or_default() as u16;
            let valve_open = parse_bool_field(line, "valve_open").unwrap_or(false);
            max_temperature = max_temperature.max(temperature);
            if valve_open {
                valve_open_iterations = valve_open_iterations.saturating_add(1);
            }
        }
    }

    let mut pcp_counts: HashMap<u8, u64> = HashMap::new();
    for line in demo_content.lines() {
        if !line.contains("Packet verify:") {
            continue;
        }
        let pcp = parse_numeric_field(line, "pcp").unwrap_or_default() as u8;
        *pcp_counts.entry(pcp).or_insert(0) += 1;
    }

    let mut ordered_pcp_counts = pcp_counts.into_iter().collect::<Vec<_>>();
    ordered_pcp_counts.sort_by_key(|entry| entry.0);

    let mut summary_lines = Vec::new();
    summary_lines.push("TSN Fieldbus Demo Post-Run Summary".to_string());
    summary_lines.push("==================================".to_string());
    summary_lines.push(format!("control_iterations={control_iterations}"));
    summary_lines.push(format!("valve_open_iterations={valve_open_iterations}"));
    summary_lines.push(format!("max_temperature_observed={max_temperature}"));
    summary_lines.push("".to_string());

    summary_lines.push("Packet PCP distribution:".to_string());
    if ordered_pcp_counts.is_empty() {
        summary_lines.push("  no_packet_verification_entries_found".to_string());
    } else {
        for (pcp, count) in ordered_pcp_counts {
            summary_lines.push(format!("  pcp_{pcp}={count}"));
        }
    }
    summary_lines.push("".to_string());

    summary_lines.extend(render_device_performance_summary(
        "temperature_slave",
        &temperature_metrics,
    ));
    summary_lines.push("".to_string());
    summary_lines.extend(render_device_performance_summary(
        "valve_slave",
        &valve_metrics,
    ));

    let summary = summary_lines.join("\n");
    let summary_path = log_directory.join(POST_RUN_SUMMARY_FILE);
    fs::write(&summary_path, summary.as_bytes())
        .map_err(|error| format!("Failed to write {}: {error}", summary_path.display()))?;

    for line in summary_lines {
        info!("[PostRunAnalyzer] {line}");
    }

    Ok(())
}
