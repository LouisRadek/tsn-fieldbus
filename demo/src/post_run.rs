use crate::logging::{
    MASTER_LOG_COMPONENT, TEMPERATURE_SLAVE_LOG_COMPONENT, VALVE_SLAVE_LOG_COMPONENT,
};
use log::info;
use std::fs;
use std::path::Path;

const POST_RUN_SUMMARY_FILE: &str = "post_run_summary.txt";

#[derive(Clone, Copy, Default)]
struct CycleStats {
    min_ns: u64,
    max_ns: u64,
    avg_ns: u64,
}

#[derive(Default)]
struct DeviceCycles {
    send: Option<CycleStats>,
    receive: Option<CycleStats>,
}

#[derive(Default)]
struct MasterControlMetrics {
    valve_open_close_cycles: u64,
    temperature_wave_iterations: u64,
}

#[derive(Default)]
struct SystemPerformanceMetrics {
    cpu_max_pct: f64,
    cpu_avg_pct: f64,
    ram_max_mib: f64,
    ram_avg_mib: f64,
    available: bool,
}

fn parse_numeric_field_u64(line: &str, field_name: &str) -> Option<u64> {
    let key = format!("{field_name}=");
    line.split_whitespace().find_map(|token| {
        token
            .trim_end_matches(',')
            .strip_prefix(&key)
            .and_then(|value| value.parse::<u64>().ok())
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

fn parse_numeric_field_f64(line: &str, field_name: &str) -> Option<f64> {
    let key = format!("{field_name}=");
    line.split_whitespace().find_map(|token| {
        token
            .trim_end_matches(',')
            .strip_prefix(&key)
            .and_then(|value| value.parse::<f64>().ok())
    })
}

fn parse_cycle_stats(line: &str) -> Option<CycleStats> {
    Some(CycleStats {
        min_ns: parse_numeric_field_u64(line, "min_ns")?,
        max_ns: parse_numeric_field_u64(line, "max_ns")?,
        avg_ns: parse_numeric_field_u64(line, "avg_ns")?,
    })
}

fn parse_device_cycles(content: &str) -> DeviceCycles {
    let mut cycles = DeviceCycles::default();

    for line in content.lines() {
        if !line.contains("L2 cycle metrics") {
            continue;
        }

        if line.contains("direction=send") {
            cycles.send = parse_cycle_stats(line);
        } else if line.contains("direction=receive") {
            cycles.receive = parse_cycle_stats(line);
        }
    }

    cycles
}

fn parse_device_jitter(content: &str) -> DeviceCycles {
    let mut jitter = DeviceCycles::default();

    for line in content.lines() {
        if !line.contains("L2 jitter metrics") {
            continue;
        }

        if line.contains("direction=send") {
            jitter.send = parse_cycle_stats(line);
        } else if line.contains("direction=receive") {
            jitter.receive = parse_cycle_stats(line);
        }
    }

    jitter
}

fn parse_master_missed_cycles(content: &str) -> u64 {
    let mut total = 0u64;

    for line in content.lines() {
        if line.contains("L2 missed cycles component=master") {
            total = parse_numeric_field_u64(line, "total").unwrap_or(total);
        }
    }

    total
}

fn parse_slave_missed_cycles(master_log: &str) -> (u64, u64) {
    let mut temperature_missed_cycles = 0u64;
    let mut valve_missed_cycles = 0u64;

    for line in master_log.lines() {
        if line.contains("Temperature status update:") {
            temperature_missed_cycles = parse_numeric_field_u64(line, "missed_cycles")
                .unwrap_or(temperature_missed_cycles);
        } else if line.contains("Valve status update:") {
            valve_missed_cycles =
                parse_numeric_field_u64(line, "missed_cycles").unwrap_or(valve_missed_cycles);
        }
    }

    (temperature_missed_cycles, valve_missed_cycles)
}

fn parse_control_metrics(master_log: &str) -> MasterControlMetrics {
    let mut metrics = MasterControlMetrics::default();
    let mut previous_valve_state: Option<bool> = None;

    enum TemperaturePhase {
        WaitingAtZero,
        Rising,
        Falling,
    }

    let mut temperature_phase = TemperaturePhase::WaitingAtZero;

    for line in master_log.lines() {
        if !line.contains("Control loop:") {
            continue;
        }

        if let Some(valve_open) = parse_bool_field(line, "valve_open") {
            if let Some(previous) = previous_valve_state
                && previous
                && !valve_open
            {
                metrics.valve_open_close_cycles =
                    metrics.valve_open_close_cycles.saturating_add(1);
            }
            previous_valve_state = Some(valve_open);
        }

        if let Some(temperature) = parse_numeric_field_u64(line, "temperature") {
            match temperature_phase {
                TemperaturePhase::WaitingAtZero => {
                    if temperature <= 5 {
                        temperature_phase = TemperaturePhase::Rising;
                    }
                }
                TemperaturePhase::Rising => {
                    if temperature >= 145 {
                        temperature_phase = TemperaturePhase::Falling;
                    }
                }
                TemperaturePhase::Falling => {
                    if temperature <= 5 {
                        metrics.temperature_wave_iterations =
                            metrics.temperature_wave_iterations.saturating_add(1);
                        temperature_phase = TemperaturePhase::Rising;
                    }
                }
            }
        }
    }

    metrics
}

fn parse_system_performance_metrics(master_log: &str) -> SystemPerformanceMetrics {
    for line in master_log.lines() {
        if !line.contains("System performance:") {
            continue;
        }

        let cpu_max_pct = parse_numeric_field_f64(line, "cpu_max_pct");
        let cpu_avg_pct = parse_numeric_field_f64(line, "cpu_avg_pct");
        let ram_max_mib = parse_numeric_field_f64(line, "ram_max_mib");
        let ram_avg_mib = parse_numeric_field_f64(line, "ram_avg_mib");

        if let (
            Some(cpu_max_pct),
            Some(cpu_avg_pct),
            Some(ram_max_mib),
            Some(ram_avg_mib),
        ) = (
            cpu_max_pct,
            cpu_avg_pct,
            ram_max_mib,
            ram_avg_mib,
        ) {
            return SystemPerformanceMetrics {
                cpu_max_pct,
                cpu_avg_pct,
                ram_max_mib,
                ram_avg_mib,
                available: true,
            };
        }
    }

    SystemPerformanceMetrics::default()
}

fn format_cycle_line(prefix: &str, stats: Option<CycleStats>) -> String {
    match stats {
        Some(stats) => {
            let min_ms = stats.min_ns as f64 / 1_000_000.0;
            let max_ms = stats.max_ns as f64 / 1_000_000.0;
            let avg_ms = stats.avg_ns as f64 / 1_000_000.0;
            format!(
                "  {prefix}: min_ms={min_ms:.3} max_ms={max_ms:.3} avg_ms={avg_ms:.3}"
            )
        }
        None => format!("  {prefix}: unavailable"),
    }
}

pub fn run_post_run_log_analysis(log_directory: &Path) -> Result<(), String> {
    let master_log_path = log_directory.join(format!("{MASTER_LOG_COMPONENT}.log"));
    let temperature_log_path =
        log_directory.join(format!("{TEMPERATURE_SLAVE_LOG_COMPONENT}.log"));
    let valve_log_path = log_directory.join(format!("{VALVE_SLAVE_LOG_COMPONENT}.log"));

    let master_content = fs::read_to_string(&master_log_path)
        .map_err(|error| format!("Failed to read {}: {error}", master_log_path.display()))?;
    let temperature_content = fs::read_to_string(&temperature_log_path)
        .map_err(|error| format!("Failed to read {}: {error}", temperature_log_path.display()))?;
    let valve_content = fs::read_to_string(&valve_log_path)
        .map_err(|error| format!("Failed to read {}: {error}", valve_log_path.display()))?;

    let master_cycles = parse_device_cycles(&master_content);
    let temperature_cycles = parse_device_cycles(&temperature_content);
    let valve_cycles = parse_device_cycles(&valve_content);
    let master_jitter = parse_device_jitter(&master_content);
    let temperature_jitter = parse_device_jitter(&temperature_content);
    let valve_jitter = parse_device_jitter(&valve_content);

    let master_missed_cycles = parse_master_missed_cycles(&master_content);
    let (temperature_missed_cycles, valve_missed_cycles) = parse_slave_missed_cycles(&master_content);
    let control_metrics = parse_control_metrics(&master_content);
    let system_performance_metrics = parse_system_performance_metrics(&master_content);

    let mut summary_lines = Vec::new();
    summary_lines.push("TSN Fieldbus Demo Post-Run Summary".to_string());
    summary_lines.push("==================================".to_string());
    summary_lines.push(format!(
        "valve_opened_and_closed_cycles={}",
        control_metrics.valve_open_close_cycles
    ));
    summary_lines.push(format!(
        "temperature_iterations_0_to_150_and_back={}",
        control_metrics.temperature_wave_iterations
    ));
    summary_lines.push("".to_string());

    summary_lines.push("master_cycle_times:".to_string());
    summary_lines.push(format_cycle_line("send", master_cycles.send));
    summary_lines.push(format_cycle_line("receive", master_cycles.receive));
    summary_lines.push("".to_string());

    summary_lines.push("temperature_slave_cycle_times:".to_string());
    summary_lines.push(format_cycle_line("send", temperature_cycles.send));
    summary_lines.push(format_cycle_line("receive", temperature_cycles.receive));
    summary_lines.push("".to_string());

    summary_lines.push("valve_slave_cycle_times:".to_string());
    summary_lines.push(format_cycle_line("send", valve_cycles.send));
    summary_lines.push(format_cycle_line("receive", valve_cycles.receive));
    summary_lines.push("".to_string());

    summary_lines.push("master_jitter_times:".to_string());
    summary_lines.push(format_cycle_line("send", master_jitter.send));
    summary_lines.push(format_cycle_line("receive", master_jitter.receive));
    summary_lines.push("".to_string());

    summary_lines.push("temperature_slave_jitter_times:".to_string());
    summary_lines.push(format_cycle_line("send", temperature_jitter.send));
    summary_lines.push(format_cycle_line("receive", temperature_jitter.receive));
    summary_lines.push("".to_string());

    summary_lines.push("valve_slave_jitter_times:".to_string());
    summary_lines.push(format_cycle_line("send", valve_jitter.send));
    summary_lines.push(format_cycle_line("receive", valve_jitter.receive));
    summary_lines.push("".to_string());

    summary_lines.push("missed_cycles:".to_string());
    summary_lines.push(format!("  master={master_missed_cycles}"));
    summary_lines.push(format!("  temperature_slave={temperature_missed_cycles}"));
    summary_lines.push(format!("  valve_slave={valve_missed_cycles}"));
    summary_lines.push("".to_string());

    summary_lines.push("system_performance:".to_string());
    if system_performance_metrics.available {
        summary_lines.push(format!(
            "  cpu_usage_max_percent={:.2}",
            system_performance_metrics.cpu_max_pct
        ));
        summary_lines.push(format!(
            "  cpu_usage_avg_percent={:.2}",
            system_performance_metrics.cpu_avg_pct
        ));
        summary_lines.push(format!(
            "  ram_usage_max_mib={:.2}",
            system_performance_metrics.ram_max_mib
        ));
        summary_lines.push(format!(
            "  ram_usage_avg_mib={:.2}",
            system_performance_metrics.ram_avg_mib
        ));
    } else {
        summary_lines.push("  unavailable".to_string());
    }

    let summary = summary_lines.join("\n");
    let summary_path = log_directory.join(POST_RUN_SUMMARY_FILE);
    fs::write(&summary_path, summary.as_bytes())
        .map_err(|error| format!("Failed to write {}: {error}", summary_path.display()))?;

    for line in summary_lines {
        info!("[PostRunAnalyzer] {line}");
    }

    Ok(())
}
