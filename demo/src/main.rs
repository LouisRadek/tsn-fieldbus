mod logging;
mod post_run;
mod vlan_monitor;

use common::demo_runtime::{
    DEMO_MASTER_INTERFACE, DEMO_TEMPERATURE_INTERFACE, DEMO_VALVE_INTERFACE, build_vlan_tag,
    setup_demo_network, teardown_demo_network, try_set_realtime_priority, vlan_priority_code_point,
};
use common::slave_api::{DeviceState, Direction, Position, StreamConfig, SubscribeStatusRequest};
use common::state_machine::DeviceStateManager;
use common::stream_store::StreamStore;
use log::{debug, error, info, warn};
use logging::{
    DEMO_LOG_COMPONENT, MASTER_LOG_COMPONENT, TEMPERATURE_SLAVE_LOG_COMPONENT,
    VALVE_SLAVE_LOG_COMPONENT, init_component_logger, set_log_component,
};
use master::{
    DiscoveryMaster, MasterProcessImage, SlaveApiClient,
    start_l2_handler as start_master_l2_handler,
};
use pnet::datalink;
use pnet::util::MacAddr;
use post_run::run_post_run_log_analysis;
use slave::{
    DeviceStatusStore, DummyHardware, PreSharedKey, TokenStore, start_discovery_listener,
    start_l2_handler as start_slave_l2_handler, start_slave_api_server,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::time;
use vlan_monitor::spawn_vlan_packet_monitor;

const LOG_DIRECTORY: &str = "logs";
const SHARED_KEY_BYTES: [u8; 32] = [
    0x31, 0x7A, 0x55, 0x9E, 0x42, 0x0B, 0x7D, 0x10, 0x2A, 0xCC, 0x6F, 0x88, 0x13, 0x47, 0xA5, 0xB1,
    0xE4, 0x2D, 0x90, 0x73, 0x1C, 0x5F, 0x6A, 0x0E, 0x99, 0xD2, 0x3B, 0x84, 0xF0, 0x11, 0x26, 0xC7,
];
const SHARED_KEY: PreSharedKey = PreSharedKey(SHARED_KEY_BYTES);

const TEMPERATURE_SLAVE_MAC: [u8; 6] = [0x02, 0x42, 0xAC, 0x10, 0x00, 0x11];
const VALVE_SLAVE_MAC: [u8; 6] = [0x02, 0x42, 0xAC, 0x10, 0x00, 0x12];
const TEMPERATURE_SLAVE_IP: [u8; 4] = [10, 10, 0, 11];
const VALVE_SLAVE_IP: [u8; 4] = [10, 10, 0, 12];
const NETMASK: [u8; 4] = [255, 255, 255, 0];
const GATEWAY: [u8; 4] = [0, 0, 0, 0];

const TEMPERATURE_STREAM_ID: u32 = 1001;
const VALVE_STREAM_ID: u32 = 1002;
const TEMPERATURE_STREAM_CYCLE_NS: u32 = 1_000_000;
const VALVE_STREAM_CYCLE_NS: u32 = 1_000_000;
const TEMPERATURE_VLAN_TAG: u16 = ((5u16) << 13) | 100;
const VALVE_VLAN_TAG: u16 = ((3u16) << 13) | 100;

#[derive(Clone, Copy)]
enum DemoSlaveRole {
    Temperature,
    Valve,
}

#[derive(Clone, Copy)]
struct DemoSlaveConfig {
    role: DemoSlaveRole,
    interface_name: &'static str,
    mac_address: [u8; 6],
    api_ip: [u8; 4],
    component: &'static str,
}

async fn wait_for_slave_state(
    client: &mut SlaveApiClient,
    expected_state: DeviceState,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let status = client
            .get_status()
            .await
            .map_err(|error| error.to_string())?;
        if status.state == expected_state as i32 {
            return Ok(());
        }
        time::sleep(Duration::from_millis(50)).await;
    }

    Err(format!("Timeout waiting for state {:?}", expected_state))
}

fn resolve_interface_mac(interface_name: &str) -> Result<MacAddr, String> {
    datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == interface_name)
        .and_then(|interface| interface.mac)
        .ok_or_else(|| format!("No MAC found for interface {interface_name}"))
}

fn to_http_endpoint(ip: [u8; 4], port: u16) -> String {
    format!("http://{}.{}.{}.{}:{port}", ip[0], ip[1], ip[2], ip[3])
}

fn spawn_temperature_wave_task(hardware: Arc<DummyHardware>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(50));
        let mut step = 0u32;
        loop {
            interval.tick().await;
            let phase = step % 200;
            let value = if phase < 100 {
                (phase * 150) / 100
            } else {
                ((200 - phase) * 150) / 100
            };
            hardware.simulate_sensor_change(value as i16);
            step = (step + 1) % 200;
        }
    })
}

fn spawn_valve_update_task(hardware: Arc<DummyHardware>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(200));
        let mut last_state = false;
        loop {
            interval.tick().await;
            let current_state = hardware.get_valve_status();
            if current_state != last_state {
                last_state = current_state;
                info!("Valve state changed: open={current_state}");
            }
        }
    })
}

fn run_slave_thread(config: DemoSlaveConfig, shared_key: PreSharedKey) -> Result<(), String> {
    set_log_component(config.component);
    info!(
        "Starting slave runtime role={} interface={} api_ip={}.{}.{}.{} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        match config.role {
            DemoSlaveRole::Temperature => "temperature",
            DemoSlaveRole::Valve => "valve",
        },
        config.interface_name,
        config.api_ip[0],
        config.api_ip[1],
        config.api_ip[2],
        config.api_ip[3],
        config.mac_address[0],
        config.mac_address[1],
        config.mac_address[2],
        config.mac_address[3],
        config.mac_address[4],
        config.mac_address[5]
    );
    if let Err(error) = try_set_realtime_priority(70) {
        warn!(
            "Unable to set real-time priority for {}: {error}",
            config.component
        );
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;

    runtime.block_on(async move {
        let hardware = match config.role {
            DemoSlaveRole::Temperature => Arc::new(DummyHardware::new_temperature_sensor(
                config.interface_name.to_string(),
                config.mac_address,
            )),
            DemoSlaveRole::Valve => Arc::new(DummyHardware::new_valve_controller(
                config.interface_name.to_string(),
                config.mac_address,
            )),
        };

        let state_manager = DeviceStateManager::new();
        state_manager
            .set_target_state(DeviceState::DiscoverySync)
            .map_err(|code| format!("Cannot enter DiscoverySync: {code:?}"))?;

        let status_store = DeviceStatusStore::new();
        status_store.update_state(DeviceState::DiscoverySync).await;

        let token_store = TokenStore::new(shared_key);
        let stream_store = StreamStore::new();

        let device_info_access = hardware.clone();
        let process_image_access = hardware.clone();
        let network_interface_access = hardware.clone();

        let discovery_handle = start_discovery_listener(
            config.interface_name,
            state_manager.clone(),
            device_info_access.clone(),
            network_interface_access,
        )
        .map_err(|code| {
            error!("Failed to start slave L2 handler: {code:?}");
            format!("Failed to start slave L2 handler: {code:?}")
        })?;

        let mut api_server_handle: Option<JoinHandle<()>> = None;
        let mut l2_handle: Option<slave::L2HandlerHandle> = None;
        let mut hardware_task: Option<JoinHandle<()>> = None;
        let mut previous_state: Option<DeviceState> = None;

        loop {
            let current_state = state_manager.get_state();
            if previous_state != Some(current_state) {
                info!("Slave state changed: {:?} -> {:?}", previous_state, current_state);
                previous_state = Some(current_state);
            }

            match current_state {
                DeviceState::DiscoverySync => {
                    time::sleep(Duration::from_millis(50)).await;
                }
                DeviceState::PreOp => {
                    if api_server_handle.is_none() {
                        info!("Starting slave API server and local hardware task in PreOp");
                        status_store.update_state(DeviceState::PreOp).await;
                        let address = SocketAddr::new(
                            Ipv4Addr::new(
                                config.api_ip[0],
                                config.api_ip[1],
                                config.api_ip[2],
                                config.api_ip[3],
                            )
                            .into(),
                            50051,
                        );

                        let server_status_store = status_store.clone();
                        let server_state_manager = state_manager.clone();
                        let server_stream_store = stream_store.clone();
                        let server_token_store = token_store.clone();
                        let server_device_info = device_info_access.clone();
                        let server_process_image = process_image_access.clone();

                        api_server_handle = Some(tokio::spawn(async move {
                            let result = start_slave_api_server(
                                address,
                                server_device_info,
                                server_process_image,
                                server_state_manager,
                                server_status_store,
                                server_token_store,
                                server_stream_store,
                            )
                            .await;
                            if let Err(error) = result {
                                warn!("Slave API server terminated: {error}");
                            }
                        }));

                        hardware_task = Some(match config.role {
                            DemoSlaveRole::Temperature => {
                                spawn_temperature_wave_task(hardware.clone())
                            }
                            DemoSlaveRole::Valve => spawn_valve_update_task(hardware.clone()),
                        });
                    }
                    time::sleep(Duration::from_millis(20)).await;
                }
                DeviceState::SafeOp | DeviceState::Op => {
                    if l2_handle.is_none() {
                        info!("Starting slave L2 handler in state {current_state:?}");
                        let handle = start_slave_l2_handler(
                            config.interface_name,
                            stream_store.clone(),
                            status_store.clone(),
                            process_image_access.clone(),
                        )
                        .map_err(|code| {
                            error!("Failed to start slave L2 handler: {code:?}");
                            format!("Failed to start slave L2 handler: {code:?}")
                        })?;
                        l2_handle = Some(handle);
                    }
                    time::sleep(Duration::from_millis(20)).await;
                }
                DeviceState::Shutdown => {
                    info!("Slave entering Shutdown state");
                    status_store.update_state(DeviceState::Shutdown).await;
                    break;
                }
                DeviceState::Error => {
                    warn!("Slave entered Error state");
                    status_store.update_state(DeviceState::Error).await;
                }
                DeviceState::Init => {
                    time::sleep(Duration::from_millis(20)).await;
                }
            }
        }

        if let Some(task) = hardware_task {
            task.abort();
            let _ = task.await;
        }

        if let Some(handle) = api_server_handle {
            handle.abort();
            let _ = handle.await;
        }

        if let Some(handle) = l2_handle {
            handle.join();
        }

        let _ = discovery_handle.join();
        Ok(())
    })
}

async fn run_master_thread() -> Result<(), String> {
    set_log_component(MASTER_LOG_COMPONENT);
    info!("Starting master runtime on interface {DEMO_MASTER_INTERFACE}");
    if let Err(error) = try_set_realtime_priority(80) {
        warn!("Unable to set real-time priority for master: {error}");
    }

    let device_state_manager = DeviceStateManager::new();
    device_state_manager
        .set_target_state(DeviceState::DiscoverySync)
        .map_err(|code| format!("Master cannot enter discovery state: {code:?}"))?;

    let mut discovery_master =
        DiscoveryMaster::new(DEMO_MASTER_INTERFACE, device_state_manager.clone())
            .map_err(|code| format!("Failed to create discovery master: {code:?}"))?;

    let mut discovered = Vec::new();
    for _ in 0..10 {
        let devices = discovery_master
            .discover_devices(Some(Duration::from_millis(1000)))
            .map_err(|code| format!("Discovery failed: {code:?}"))?;
        if !devices.is_empty() {
            discovered.extend(devices);
        }
        if discovery_master.discovered_devices().len() >= 2 {
            break;
        }
        time::sleep(Duration::from_millis(200)).await;
    }

    if discovery_master.discovered_devices().len() < 2 {
        return Err("Did not discover both slave devices".to_string());
    }

    let mut temperature_mac: Option<MacAddr> = None;
    let mut valve_mac: Option<MacAddr> = None;

    for device in discovery_master.discovered_devices().values() {
        if device.device_id == 1 {
            temperature_mac = Some(device.mac_address);
        } else if device.device_id == 2 {
            valve_mac = Some(device.mac_address);
        }
    }

    let temperature_mac =
        temperature_mac.ok_or_else(|| "Temperature slave not found".to_string())?;
    let valve_mac = valve_mac.ok_or_else(|| "Valve slave not found".to_string())?;

    info!("Discovered slaves: temperature={temperature_mac}, valve={valve_mac}");

    discovery_master
        .set_ip_config(
            temperature_mac,
            TEMPERATURE_SLAVE_IP,
            NETMASK,
            GATEWAY,
            Some(Duration::from_secs(1)),
        )
        .map_err(|code| format!("Failed to set temperature slave IP: {code:?}"))?;

    discovery_master
        .set_ip_config(
            valve_mac,
            VALVE_SLAVE_IP,
            NETMASK,
            GATEWAY,
            Some(Duration::from_secs(1)),
        )
        .map_err(|code| format!("Failed to set valve slave IP: {code:?}"))?;

    time::sleep(Duration::from_secs(1)).await;

    info!("Transitioning master state to PreOp");
    device_state_manager
        .set_target_state(DeviceState::PreOp)
        .map_err(|code| format!("Master transition to PreOp failed: {code:?}"))?;

    let mut temperature_client = SlaveApiClient::connect(
        to_http_endpoint(TEMPERATURE_SLAVE_IP, 50051),
        SHARED_KEY_BYTES.to_vec(),
    )
    .await
    .map_err(|error| format!("Failed to connect temperature slave API: {error}"))?;

    let mut valve_client = SlaveApiClient::connect(
        to_http_endpoint(VALVE_SLAVE_IP, 50051),
        SHARED_KEY_BYTES.to_vec(),
    )
    .await
    .map_err(|error| format!("Failed to connect valve slave API: {error}"))?;

    let temperature_info = temperature_client
        .get_device_info()
        .await
        .map_err(|error| error.to_string())?;
    let valve_info = valve_client
        .get_device_info()
        .await
        .map_err(|error| error.to_string())?;

    info!(
        "Temperature slave info status={} Valve slave info status={}",
        temperature_info.code, valve_info.code
    );

    let mut temperature_status_stream = temperature_client
        .subscribe_to_device_status(SubscribeStatusRequest {
            min_interval_sec: Some(10),
        })
        .await
        .map_err(|error| error.to_string())?;

    let mut valve_status_stream = valve_client
        .subscribe_to_device_status(SubscribeStatusRequest {
            min_interval_sec: Some(10),
        })
        .await
        .map_err(|error| error.to_string())?;

    let status_task_temperature = tokio::spawn(async move {
        loop {
            match temperature_status_stream.message().await {
                Ok(Some(status)) => info!(
                    "Temperature status update: state={} status_code={} missed_cycles={} min_cycle_time_ns={} max_cycle_time_ns={}",
                    status.state,
                    status.status_code,
                    status.missed_cycles,
                    status.min_cycle_time,
                    status.max_cycle_time
                ),
                Ok(None) => break,
                Err(error) => {
                    warn!("Temperature status stream failed: {error}");
                    break;
                }
            }
        }
    });

    let status_task_valve = tokio::spawn(async move {
        loop {
            match valve_status_stream.message().await {
                Ok(Some(status)) => info!(
                    "Valve status update: state={} status_code={} missed_cycles={} min_cycle_time_ns={} max_cycle_time_ns={}",
                    status.state,
                    status.status_code,
                    status.missed_cycles,
                    status.min_cycle_time,
                    status.max_cycle_time
                ),
                Ok(None) => break,
                Err(error) => {
                    warn!("Valve status stream failed: {error}");
                    break;
                }
            }
        }
    });

    let master_mac = resolve_interface_mac(DEMO_MASTER_INTERFACE)?;
    let temperature_stream_master = StreamConfig {
        stream_id: TEMPERATURE_STREAM_ID,
        destination_mac: master_mac.octets().to_vec(),
        vlan_id_pcp: build_vlan_tag(100, 6) as u32,
        cycle_time_nano: TEMPERATURE_STREAM_CYCLE_NS,
        direction: Direction::Input as i32,
        stream_content: Some(Position {
            byte_offset: 0,
            bit_offset: 0,
            bit_len: 16,
        }),
    };

    let valve_stream_master = StreamConfig {
        stream_id: VALVE_STREAM_ID,
        destination_mac: valve_mac.octets().to_vec(),
        vlan_id_pcp: build_vlan_tag(100, 6) as u32,
        cycle_time_nano: VALVE_STREAM_CYCLE_NS,
        direction: Direction::Output as i32,
        stream_content: Some(Position {
            byte_offset: 0,
            bit_offset: 0,
            bit_len: 1,
        }),
    };

    let temperature_stream_slave = StreamConfig {
        destination_mac: master_mac.octets().to_vec(),
        direction: Direction::Output as i32,
        ..temperature_stream_master.clone()
    };

    let valve_stream_slave = StreamConfig {
        destination_mac: valve_mac.octets().to_vec(),
        direction: Direction::Input as i32,
        ..valve_stream_master.clone()
    };

    temperature_client
        .configure_streams(vec![temperature_stream_slave])
        .await
        .map_err(|error| error.to_string())?;
    info!(
        "Configured temperature stream on slave stream_id={} direction=Output vlan=0x{:04x}",
        TEMPERATURE_STREAM_ID,
        build_vlan_tag(100, 5)
    );
    valve_client
        .configure_streams(vec![valve_stream_slave])
        .await
        .map_err(|error| error.to_string())?;
    info!(
        "Configured valve stream on slave stream_id={} direction=Input vlan=0x{:04x}",
        VALVE_STREAM_ID,
        build_vlan_tag(100, 3)
    );

    let stream_store = StreamStore::new();
    stream_store
        .add_stream_config(temperature_stream_master)
        .map_err(|code| format!("Failed to add master input stream: {code:?}"))?;

    stream_store
        .add_stream_config(valve_stream_master)
        .map_err(|code| format!("Failed to add master output stream: {code:?}"))?;

    info!("Transitioning master state to SafeOp");
    device_state_manager
        .set_target_state(DeviceState::SafeOp)
        .map_err(|code| format!("Master transition to SafeOp failed: {code:?}"))?;

    let process_image = Arc::new(MasterProcessImage::new());
    let l2_handler = start_master_l2_handler(
        DEMO_MASTER_INTERFACE,
        stream_store,
        device_state_manager.clone(),
        process_image.clone(),
    )
    .map_err(|code| format!("Failed to start master L2 handler: {code:?}"))?;

    temperature_client
        .set_target_state(DeviceState::SafeOp)
        .await
        .map_err(|error| error.to_string())?;
    valve_client
        .set_target_state(DeviceState::SafeOp)
        .await
        .map_err(|error| error.to_string())?;

    wait_for_slave_state(
        &mut temperature_client,
        DeviceState::SafeOp,
        Duration::from_secs(5),
    )
    .await?;
    wait_for_slave_state(
        &mut valve_client,
        DeviceState::SafeOp,
        Duration::from_secs(5),
    )
    .await?;

    let start_wait = Instant::now();
    let mut last_wait_log = Instant::now();
    while start_wait.elapsed() < Duration::from_secs(5) {
        let current_temperature = process_image.read_temperature_u16();
        if current_temperature > 0 {
            info!(
                "Received first temperature sample in SafeOp: {}",
                current_temperature
            );
            break;
        }

        if last_wait_log.elapsed() >= Duration::from_secs(1) {
            debug!(
                "Waiting for SafeOp process data from temperature slave (elapsed={}ms)",
                start_wait.elapsed().as_millis()
            );
            last_wait_log = Instant::now();
        }

        time::sleep(Duration::from_millis(50)).await;
    }

    info!("Transitioning slaves to Op and then master to Op");
    temperature_client
        .set_target_state(DeviceState::Op)
        .await
        .map_err(|error| error.to_string())?;
    valve_client
        .set_target_state(DeviceState::Op)
        .await
        .map_err(|error| error.to_string())?;

    wait_for_slave_state(
        &mut temperature_client,
        DeviceState::Op,
        Duration::from_secs(5),
    )
    .await?;
    wait_for_slave_state(&mut valve_client, DeviceState::Op, Duration::from_secs(5)).await?;

    device_state_manager
        .set_target_state(DeviceState::Op)
        .map_err(|code| format!("Master transition to Op failed: {code:?}"))?;

    let mut interval = time::interval(Duration::from_millis(2));
    let operation_start = Instant::now();
    let mut previous_temperature = 0u16;
    let mut previous_valve_state = false;
    while operation_start.elapsed() < Duration::from_secs(30) {
        interval.tick().await;
        let temperature = process_image.read_temperature_u16();
        let valve_open = temperature > 100;
        process_image.write_valve_state(valve_open);

        if previous_temperature != temperature || previous_valve_state != valve_open {
            debug!(
                "Control loop: temperature={} valve_open={}",
                temperature, valve_open
            );
            previous_temperature = temperature;
            previous_valve_state = valve_open
        }
    }

    let _ = temperature_client
        .set_target_state(DeviceState::Shutdown)
        .await;
    let _ = valve_client.set_target_state(DeviceState::Shutdown).await;
    let _ = wait_for_slave_state(
        &mut temperature_client,
        DeviceState::Shutdown,
        Duration::from_secs(5),
    )
    .await;
    let _ = wait_for_slave_state(
        &mut valve_client,
        DeviceState::Shutdown,
        Duration::from_secs(5),
    )
    .await;

    device_state_manager
        .set_target_state(DeviceState::Shutdown)
        .map_err(|code| format!("Master transition to Shutdown failed: {code:?}"))?;

    l2_handler.join();

    status_task_temperature.abort();
    status_task_valve.abort();

    info!(
        "Configured VLAN Tag values: temperature=0x{:04x} (pcp={}), valve=0x{:04x} (pcp={})",
        TEMPERATURE_VLAN_TAG,
        vlan_priority_code_point(TEMPERATURE_VLAN_TAG),
        VALVE_VLAN_TAG,
        vlan_priority_code_point(VALVE_VLAN_TAG)
    );

    Ok(())
}

fn main() {
    set_log_component(DEMO_LOG_COMPONENT);

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("This demo requires root privileges for raw L2 sockets and virtual interfaces.");
        std::process::exit(1);
    }

    if let Err(error) = init_component_logger(&PathBuf::from(LOG_DIRECTORY)) {
        eprintln!("Failed to initialize logger: {error}");
        std::process::exit(1);
    }

    info!("Initializing TSN fieldbus demo runtime");

    if let Err(error) = setup_demo_network() {
        error!("Failed to setup demo network: {error}");
        std::process::exit(1);
    }

    let stop_monitor = Arc::new(AtomicBool::new(false));
    let monitor_handle = spawn_vlan_packet_monitor(stop_monitor.clone());

    let temperature_slave = DemoSlaveConfig {
        role: DemoSlaveRole::Temperature,
        interface_name: DEMO_TEMPERATURE_INTERFACE,
        mac_address: TEMPERATURE_SLAVE_MAC,
        api_ip: TEMPERATURE_SLAVE_IP,
        component: TEMPERATURE_SLAVE_LOG_COMPONENT,
    };

    let valve_slave = DemoSlaveConfig {
        role: DemoSlaveRole::Valve,
        interface_name: DEMO_VALVE_INTERFACE,
        mac_address: VALVE_SLAVE_MAC,
        api_ip: VALVE_SLAVE_IP,
        component: VALVE_SLAVE_LOG_COMPONENT,
    };

    let temperature_thread = thread::Builder::new()
        .name("slave-temp".to_string())
        .spawn(move || run_slave_thread(temperature_slave, SHARED_KEY))
        .expect("Failed to spawn temperature slave thread");

    let valve_thread = thread::Builder::new()
        .name("slave-valve".to_string())
        .spawn(move || run_slave_thread(valve_slave, SHARED_KEY))
        .expect("Failed to spawn valve slave thread");

    thread::sleep(Duration::from_millis(500));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("master-runtime")
        .build()
        .expect("Failed to create master runtime");

    let master_result = runtime.block_on(run_master_thread());
    if let Err(error) = master_result {
        error!("Master demo execution failed: {error}");
    }

    match temperature_thread.join() {
        Ok(Ok(())) => info!("Temperature slave thread exited cleanly"),
        Ok(Err(error)) => error!("Temperature slave failed: {error}"),
        Err(_) => error!("Temperature slave thread panicked"),
    }

    match valve_thread.join() {
        Ok(Ok(())) => info!("Valve slave thread exited cleanly"),
        Ok(Err(error)) => error!("Valve slave failed: {error}"),
        Err(_) => error!("Valve slave thread panicked"),
    }

    stop_monitor.store(true, Ordering::Relaxed);
    let _ = monitor_handle.join();

    if let Err(error) = teardown_demo_network() {
        warn!("Demo network teardown reported an issue: {error}");
    }

    if let Err(error) = run_post_run_log_analysis(&PathBuf::from(LOG_DIRECTORY)) {
        warn!("Post-run log analyzer failed: {error}");
    }

    info!("Demo completed");
}
