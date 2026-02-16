use log::{LevelFilter, Log};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::thread;

pub const MASTER_LOG_COMPONENT: &str = "master";
pub const TEMPERATURE_SLAVE_LOG_COMPONENT: &str = "slave-temperature";
pub const VALVE_SLAVE_LOG_COMPONENT: &str = "slave-valve";
pub const DEMO_LOG_COMPONENT: &str = "demo";

thread_local! {
    static LOG_COMPONENT: RefCell<String> = RefCell::new(DEMO_LOG_COMPONENT.to_string());
}

struct ComponentFileLogger {
    level: LevelFilter,
    files: Mutex<HashMap<String, std::fs::File>>,
}

static LOGGER: OnceLock<ComponentFileLogger> = OnceLock::new();

impl Log for ComponentFileLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let mut component = current_log_component();
        if component == DEMO_LOG_COMPONENT
            && let Some(name) = thread::current().name()
        {
            if name.contains("master") {
                component = MASTER_LOG_COMPONENT.to_string();
            } else if name.contains("temp") {
                component = TEMPERATURE_SLAVE_LOG_COMPONENT.to_string();
            } else if name.contains("valve") {
                component = VALVE_SLAVE_LOG_COMPONENT.to_string();
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let line = format!(
            "{timestamp} [{}] [{}] {}\n",
            record.level(),
            record.target(),
            record.args()
        );

        let mut guard = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(file) = guard.get_mut(&component) {
            let _ = file.write_all(line.as_bytes());
        } else if let Some(file) = guard.get_mut(DEMO_LOG_COMPONENT) {
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn flush(&self) {}
}

fn current_log_component() -> String {
    LOG_COMPONENT.with(|component| component.borrow().clone())
}

pub fn set_log_component(component: &str) {
    LOG_COMPONENT.with(|value| {
        *value.borrow_mut() = component.to_string();
    });
}

pub fn init_component_logger(log_directory: &Path) -> Result<(), String> {
    fs::create_dir_all(log_directory).map_err(|error| error.to_string())?;

    let mut files = HashMap::new();
    for component in [
        MASTER_LOG_COMPONENT,
        TEMPERATURE_SLAVE_LOG_COMPONENT,
        VALVE_SLAVE_LOG_COMPONENT,
        DEMO_LOG_COMPONENT,
    ] {
        let path = log_directory.join(format!("{component}.log"));
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|error| error.to_string())?;
        files.insert(component.to_string(), file);
    }

    let logger = ComponentFileLogger {
        level: LevelFilter::Debug,
        files: Mutex::new(files),
    };

    let logger_ref = LOGGER.get_or_init(|| logger);
    log::set_logger(logger_ref).map_err(|error| error.to_string())?;
    log::set_max_level(LevelFilter::Debug);
    Ok(())
}
