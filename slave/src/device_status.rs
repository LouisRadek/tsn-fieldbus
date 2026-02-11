//! Device status storage and broadcast utilities.
//!
//! This module maintains an in-memory `DeviceStatus` snapshot, a broadcast
//! channel for subscribers, and a bounded log of recent `LogEntryDeviceStatus`
//! entries. It also provides background tasks for polling a temperature
//! sensor and producing periodic heartbeat log entries.
//!
//! The store is intended for use by the slave runtime to publish status
//! updates to connected masters via the gRPC `SubscribeToDeviceStatus` stream.
//!
use log::{error, info, warn};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use common::{
    hardware_abstraction::TemperatureSensorAccess,
    slave_api::{
        DeviceState, DeviceStatus, LogEntryDeviceStatus, LogReason, StatusCode, SyncStatus,
    },
};
use tokio::sync::{RwLock, broadcast};
use tokio::time;

const STATUS_BROADCAST_CAPACITY: usize = 16;
const TEMPERATURE_THRESHOLD: u16 = 5;
const TEMPERATURE_READ_INTERVAL_SEC: u16 = 10;
const LOG_INTERVAL_SEC: u16 = 60;
// Number of entries to get the logs of roughly 1h depending on the number of event-based logs.
const LOG_CAPACITY: usize = (60 / LOG_INTERVAL_SEC as usize) * 60;

#[derive(Clone)]
pub struct DeviceStatusStore {
    /// Current device status snapshot.
    current: Arc<RwLock<DeviceStatus>>,
    /// Broadcast channel for real-time status updates.
    broadcaster: broadcast::Sender<DeviceStatus>,
    /// Ring-buffer of recent log entries.
    log_entries: Arc<Mutex<VecDeque<LogEntryDeviceStatus>>>,
}

impl Default for DeviceStatusStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceStatusStore {
    pub fn new() -> Self {
        let (broadcaster, _) = broadcast::channel(STATUS_BROADCAST_CAPACITY);
        Self {
            current: Arc::new(RwLock::new(DeviceStatus {
                status_code: StatusCode::NoError.into(),
                state: DeviceState::Init.into(),
                sync_status: SyncStatus::Syncing.into(),
                missed_cycles: 0,
                min_cycle_time: 0,
                max_cycle_time: 0,
                temperature: 0,
                timestamp: generate_timestamp(),
            })),
            broadcaster,
            log_entries: Arc::new(Mutex::new(VecDeque::with_capacity(LOG_CAPACITY))),
        }
    }

    /// Spawn background tasks for temperature polling and periodic logging.
    ///
    /// - Temperature task: reads the sensor every `TEMPERATURE_READ_INTERVAL_SEC`
    ///   and publishes an update when the absolute difference to the last
    ///   published value is >= `TEMPERATURE_THRESHOLD`.
    /// - Logging task: appends a heartbeat log entry every `LOG_INTERVAL_SEC`.
    pub fn spawn_background_tasks(
        &self,
        sensor: Arc<dyn TemperatureSensorAccess>,
    ) -> Result<(), StatusCode> {
        let temp_store = self.clone();
        let current_temperatur_polling = self.current.clone();
        let current_heartbeat_logging = self.current.clone();

        tokio::spawn(async move {
            info!("Temperature polling background task started");
            let mut interval =
                time::interval(Duration::from_secs(TEMPERATURE_READ_INTERVAL_SEC as u64));
            let mut last_published: i16 = match sensor.read_temperature() {
                Ok(temp) => temp,
                Err(e) => {
                    error!("Failed to read initial temperature: {e:?}");
                    0
                }
            };
            loop {
                interval.tick().await;

                let state = { current_temperatur_polling.clone().blocking_read().state };
                if state == DeviceState::Error as i32 || state == DeviceState::Shutdown as i32 {
                    warn!(
                        "Temperatur polling backgroud task terminated, because device state is {state}"
                    );
                    break;
                }

                match sensor.read_temperature() {
                    Ok(temperature) => {
                        let has_to_be_published = (temperature - last_published).unsigned_abs()
                            as u32
                            >= TEMPERATURE_THRESHOLD as u32;

                        if has_to_be_published {
                            last_published = temperature;
                            temp_store.update_temperature(temperature as i32).await;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read temperature: {e:?}");
                    }
                }
            }
        });

        let log_store = self.clone();
        tokio::spawn(async move {
            info!("Heartbeat logging background task started");
            let mut interval = time::interval(Duration::from_secs(LOG_INTERVAL_SEC as u64));
            loop {
                interval.tick().await;
                let state = { current_heartbeat_logging.blocking_read().state };
                if state == DeviceState::Error as i32 || state == DeviceState::Shutdown as i32 {
                    warn!(
                        "Heartbeat logging backgroud task terminated, because device state is {state}"
                    );
                    break;
                }

                let status = log_store.get_status().await;
                log_store.append_log(LogReason::Heartbeat, &status);
            }
        });

        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DeviceStatus> {
        self.broadcaster.subscribe()
    }

    pub async fn get_status(&self) -> DeviceStatus {
        *self.current.read().await
    }

    pub async fn update_status_code(&self, status_code: StatusCode) {
        let mut current = self.current.write().await;

        if current.status_code != status_code.into() {
            current.status_code = status_code.into();
        }

        let status = *current;
        self.append_log(LogReason::StatusCodeChange, &status);
        let _ = self.broadcaster.send(status);
    }

    pub async fn update_state(&self, state: DeviceState) {
        let mut current = self.current.write().await;

        if current.state != state.into() {
            current.state = state.into();
            current.timestamp = generate_timestamp();
        }

        let status = *current;
        self.append_log(LogReason::StateChange, &status);
        let _ = self.broadcaster.send(status);
    }

    pub async fn update_sync_status(&self, sync_status: SyncStatus) {
        let mut current = self.current.write().await;

        if current.sync_status != sync_status.into() {
            current.sync_status = sync_status.into();
            current.timestamp = generate_timestamp();
        }

        let status = *current;
        self.append_log(LogReason::SyncStatusChange, &status);
        let _ = self.broadcaster.send(status);
    }

    pub async fn increment_missed_cycles_by(&self, count: u32) {
        if count == 0 {
            return;
        }

        let mut current = self.current.write().await;

        current.missed_cycles = current.missed_cycles.saturating_add(count);
        current.timestamp = generate_timestamp();

        let status = *current;
        self.append_log(LogReason::MissedCycle, &status);
        let _ = self.broadcaster.send(status);
    }

    pub async fn update_min_cycle_time(&self, new_value: u32) {
        let mut current = self.current.write().await;

        if current.min_cycle_time > new_value {
            current.min_cycle_time = new_value;
            current.timestamp = generate_timestamp();
        }
    }

    pub async fn update_max_cycle_time(&self, new_value: u32) {
        let mut current = self.current.write().await;

        if current.max_cycle_time < new_value {
            current.max_cycle_time = new_value;
            current.timestamp = generate_timestamp();
        }
    }

    pub async fn update_temperature(&self, new_value: i32) {
        let mut current = self.current.write().await;

        if current.temperature != new_value {
            current.temperature = new_value;
            current.timestamp = generate_timestamp();
        }

        let status = *current;
        self.append_log(LogReason::TemperatureChange, &status);
        let _ = self.broadcaster.send(status);
    }

    fn append_log(&self, reason: LogReason, status: &DeviceStatus) {
        let mut log = match self.log_entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("DeviceStatus log_entries mutex poisoned");
                poisoned.into_inner()
            }
        };
        if log.len() == LOG_CAPACITY {
            log.pop_back();
        }
        log.push_front(LogEntryDeviceStatus {
            log_reason: reason as i32,
            device_status: Some(*status),
        });
    }

    /// Retrieve a slice of the stored log entries.
    ///
    /// Returns `(total_entries, entries)` where `entries` is the requested
    /// window starting at `offset` with at most `limit` elements.
    pub fn get_log(&self, offset: usize, limit: usize) -> (u32, Vec<LogEntryDeviceStatus>) {
        let log = match self.log_entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("DeviceStatus log_entries mutex poisoned in get_log");
                poisoned.into_inner()
            }
        };
        let total = log.len();
        let entries = log
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        (total as u32, entries)
    }
}

fn generate_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_initial_status_defaults() {
        let store = DeviceStatusStore::new();
        let status = store.get_status().await;

        assert_eq!(status.status_code, StatusCode::NoError as i32);
        assert_eq!(status.state, DeviceState::Init as i32);
        assert_eq!(status.temperature, 0);
    }

    #[tokio::test]
    async fn test_update_state_broadcasts_and_logs() {
        let store = DeviceStatusStore::new();
        let mut receiver = store.subscribe();

        store.update_state(DeviceState::DiscoverySync).await;

        let received = timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("timeout waiting for broadcast")
            .expect("broadcast receive failed");

        assert_eq!(received.state, DeviceState::DiscoverySync as i32);

        let (total, entries) = store.get_log(0, 5);
        assert!(total >= 1);
        assert_eq!(entries[0].log_reason, LogReason::StateChange as i32);
    }

    #[tokio::test]
    async fn test_update_temperature_logs_and_updates() {
        let store = DeviceStatusStore::new();
        let mut receiver = store.subscribe();

        store.update_temperature(42).await;

        let received = timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("timeout waiting for broadcast")
            .expect("broadcast receive failed");

        assert_eq!(received.temperature, 42);

        let (total, entries) = store.get_log(0, 5);
        assert!(total >= 1);
        assert_eq!(entries[0].log_reason, LogReason::TemperatureChange as i32);
    }

    #[tokio::test]
    async fn test_log_pagination() {
        let store = DeviceStatusStore::new();

        store.update_state(DeviceState::DiscoverySync).await;
        store.update_temperature(10).await;
        store.update_temperature(20).await;

        let (total, first_page) = store.get_log(0, 2);
        let (_, second_page) = store.get_log(2, 2);

        assert!(total >= 3);
        assert_eq!(first_page.len(), 2);
        assert_eq!(second_page.len(), 1);
    }
}
