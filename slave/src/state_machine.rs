#![allow(dead_code)]
//! Device state machine.
//!
//! This module implements a finite state machine for controlling the lifecycle
//! and operational states of a fieldbus slave device. The state machine enforces
//! valid state transitions and provides thread-safe state management.
//!
//! # States
//!
//! - **Init**: Initial startup state, transitions to DiscoverySync
//! - **DiscoverySync**: Waiting for discovery, clock sync, and IP configuration
//! - **PreOp**: Device configuration by the master (CUC)
//! - **SafeOp**: Sensors active but actuators disabled
//! - **Op**: Full real-time operation
//! - **Error**: Error condition; outputs frozen, diagnostics available
//! - **Shutdown**: Terminal state for graceful shutdown
//!
//! # Thread Safety
//!
//! The [`DeviceStateManager`] uses `Arc<Mutex<DeviceState>>` to provide thread-safe
//! access to the device state. Multiple threads can safely call state transition methods
//! concurrently.

use common::slave_api::DeviceState;
use common::status_codes::StatusCode;
use log::{error, info, warn};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct DeviceStateManager {
    state: Arc<Mutex<DeviceState>>,
}

impl DeviceStateManager {
    /// Creates a new device state manager initialized to the `Init` state.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(DeviceState::Init)),
        }
    }

    pub fn get_state(&self) -> DeviceState {
        *self.state.lock().unwrap()
    }

    /// Attempts to transition the device to a target state.
    ///
    /// This method validates the transition against the state machine rules.
    /// If the transition is valid, the state is updated and `Ok(())` is returned.
    /// If the transition is invalid, `Err(StateConflict)` is returned and the state remains unchanged.
    ///
    /// # Valid transitions
    ///
    /// - `Init` → `DiscoverySync`, `Error`
    /// - `DiscoverySync` → `PreOp`, `Error`
    /// - `PreOp` → `SafeOp`, `Error`
    /// - `SafeOp` → `PreOp`, `Op`, `Shutdown`, `Error`
    /// - `Op` → `SafeOp`, `Shutdown`, `Error`
    /// - `Error` → `Init` (restart)
    /// - `Shutdown` → (terminal state)
    /// - Transitions to the same state are also always valid.
    ///
    /// # Errors
    ///
    /// Returns `Err(StatusCode::StateConflict)` if the requested transition is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// let manager = DeviceStateManager::new();
    /// assert!(manager.set_target_state(DeviceState::DiscoverySync).is_ok());
    /// assert!(manager.set_target_state(DeviceState::Op).is_err()); // Invalid: must go through PreOp
    /// ```
    pub fn set_target_state(&self, target: DeviceState) -> Result<(), StatusCode> {
        let mut current = self.state.lock().unwrap();

        match (*current, target) {
            (DeviceState::Init, DeviceState::DiscoverySync) => {
                info!("Startup Complete. Transitioning INIT -> DISCOVERY/SYNC");
                *current = target;
                Ok(())
            }

            (DeviceState::DiscoverySync, DeviceState::PreOp) => {
                info!("Device Discovered & Synced. Transitioning DISCOVERY/SYNC -> PRE_OP");
                *current = target;
                Ok(())
            }

            (DeviceState::PreOp, DeviceState::SafeOp) => {
                info!("Configuration Complete. Transitioning PRE_OP -> SAFE_OP");
                *current = target;
                Ok(())
            }

            (DeviceState::SafeOp, DeviceState::PreOp) => {
                info!("Reconfiguration. Transitioning SAFE_OP -> PRE_OP");
                *current = target;
                Ok(())
            }

            (DeviceState::SafeOp, DeviceState::Op) => {
                info!("Entering Full Operation. Transitioning SAFE_OP -> OP");
                *current = target;
                Ok(())
            }

            (DeviceState::SafeOp, DeviceState::Shutdown) => {
                info!("Device shutdown triggered from SAFE_OP");
                *current = target;
                Ok(())
            }

            (DeviceState::Op, DeviceState::SafeOp) => {
                warn!("Downgrading to SAFE_OP: requested or mild error condition");
                *current = target;
                Ok(())
            }

            (DeviceState::Op, DeviceState::Shutdown) => {
                info!("Device shutdown triggered from OP");
                *current = target;
                Ok(())
            }

            (DeviceState::Error, DeviceState::Init) => {
                info!("Device restart requested from ERROR state. Transitioning ERROR -> INIT");
                *current = target;
                Ok(())
            }

            (c, t) if c == t => Ok(()),

            (_, DeviceState::Error) => {
                error!("Critical Failure. Entering ERROR state");
                *current = target;
                Ok(())
            }

            (c, t) => {
                warn!("Invalid State Transition request: {c:?} -> {t:?}");
                Err(StatusCode::StateConflict)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let manager = DeviceStateManager::new();
        assert_eq!(manager.get_state(), DeviceState::Init);
    }

    #[test]
    fn test_valid_init_to_discovery() {
        let manager = DeviceStateManager::new();
        assert!(manager.set_target_state(DeviceState::DiscoverySync).is_ok());
        assert_eq!(manager.get_state(), DeviceState::DiscoverySync);
    }

    #[test]
    fn test_valid_discovery_to_preop() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        assert!(manager.set_target_state(DeviceState::PreOp).is_ok());
        assert_eq!(manager.get_state(), DeviceState::PreOp);
    }

    #[test]
    fn test_valid_preop_to_safeop() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        assert!(manager.set_target_state(DeviceState::SafeOp).is_ok());
        assert_eq!(manager.get_state(), DeviceState::SafeOp);
    }

    #[test]
    fn test_valid_safeop_to_op() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        manager.set_target_state(DeviceState::SafeOp).unwrap();
        assert!(manager.set_target_state(DeviceState::Op).is_ok());
        assert_eq!(manager.get_state(), DeviceState::Op);
    }

    #[test]
    fn test_valid_op_to_safeop() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        manager.set_target_state(DeviceState::SafeOp).unwrap();
        manager.set_target_state(DeviceState::Op).unwrap();
        assert!(manager.set_target_state(DeviceState::SafeOp).is_ok());
        assert_eq!(manager.get_state(), DeviceState::SafeOp);
    }

    #[test]
    fn test_valid_safeop_to_preop() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        manager.set_target_state(DeviceState::SafeOp).unwrap();
        assert!(manager.set_target_state(DeviceState::PreOp).is_ok());
        assert_eq!(manager.get_state(), DeviceState::PreOp);
    }

    #[test]
    fn test_valid_safeop_to_shutdown() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        manager.set_target_state(DeviceState::SafeOp).unwrap();
        assert!(manager.set_target_state(DeviceState::Shutdown).is_ok());
        assert_eq!(manager.get_state(), DeviceState::Shutdown);
    }

    #[test]
    fn test_valid_op_to_shutdown() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        manager.set_target_state(DeviceState::SafeOp).unwrap();
        manager.set_target_state(DeviceState::Op).unwrap();
        assert!(manager.set_target_state(DeviceState::Shutdown).is_ok());
        assert_eq!(manager.get_state(), DeviceState::Shutdown);
    }

    #[test]
    fn test_valid_error_to_init() {
        let manager = DeviceStateManager::new();
        manager.set_target_state(DeviceState::Error).unwrap();
        assert!(manager.set_target_state(DeviceState::Init).is_ok());
        assert_eq!(manager.get_state(), DeviceState::Init);
    }

    #[test]
    fn test_same_state_transition() {
        let manager = DeviceStateManager::new();
        assert!(manager.set_target_state(DeviceState::Init).is_ok());
        assert_eq!(manager.get_state(), DeviceState::Init);
    }

    #[test]
    fn test_error_transition_from_any_state() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        assert!(manager.set_target_state(DeviceState::Error).is_ok());
        assert_eq!(manager.get_state(), DeviceState::Error);
    }

    #[test]
    fn test_invalid_init_to_preop() {
        let manager = DeviceStateManager::new();
        assert!(manager.set_target_state(DeviceState::PreOp).is_err());
        assert_eq!(manager.get_state(), DeviceState::Init);
    }

    #[test]
    fn test_invalid_init_to_op() {
        let manager = DeviceStateManager::new();
        assert!(manager.set_target_state(DeviceState::Op).is_err());
        assert_eq!(manager.get_state(), DeviceState::Init);
    }

    #[test]
    fn test_invalid_discovery_to_op() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        assert!(manager.set_target_state(DeviceState::Op).is_err());
        assert_eq!(manager.get_state(), DeviceState::DiscoverySync);
    }

    #[test]
    fn test_invalid_preop_to_op() {
        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        assert!(manager.set_target_state(DeviceState::Op).is_err());
        assert_eq!(manager.get_state(), DeviceState::PreOp);
    }

    #[test]
    fn test_thread_safety() {
        use std::thread;

        let manager = DeviceStateManager::new();
        manager
            .set_target_state(DeviceState::DiscoverySync)
            .unwrap();
        manager.set_target_state(DeviceState::PreOp).unwrap();
        manager.set_target_state(DeviceState::SafeOp).unwrap();

        let manager_clone = manager.clone();

        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let _ = manager_clone.get_state();
            }
        });

        for _ in 0..100 {
            let _ = manager.get_state();
        }

        handle.join().unwrap();
        assert_eq!(manager.get_state(), DeviceState::SafeOp);
    }
}
