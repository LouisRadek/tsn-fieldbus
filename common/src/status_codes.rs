use thiserror::Error;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusCode {
    #[error("Success")]
    NoError = 0x00,

    #[error("PTP sync lost")]
    PtpSyncLost = 0x01,

    #[error("Cycle counter mismatch")]
    CycleCounterMismatch = 0x02,

    #[error("Deadline missed")]
    DeadlineMissed = 0x03,

    #[error("Stream ID unknown")]
    StreamIdUnknown = 0x04,

    #[error("Payload size did not match the expected size for this Stream ID")]
    InvalidLen = 0x05,

    #[error("Hardware is not responding")]
    AppNotResponding = 0x06,

    #[error("Peripheral fault, e.g. a wire break")]
    PeripheralFault = 0x07,

    #[error("Device is in the wrong state to process the operation")]
    NotReady = 0x08,

    #[error("Access denied, you need to authenticate")]
    AccessDenied = 0x09,

    #[error("Authentication failed")]
    AuthFailed = 0x0A,

    #[error("Invalid transition")]
    StateConflict = 0x0B,

    #[error("Invalid parameter")]
    ParamInvalid = 0x0C,

    #[error("No memory available")]
    NoMemory = 0x0D,

    #[error("Operation not supported")]
    NotSupported = 0x0E,

    #[error("Service already running")]
    AlreadyRunning = 0x0F,

    #[error("OS Failure")]
    OsFailure = 0x10,

    #[error("IP Conflict")]
    IpConflict = 0x11,

    #[error("Application version mismatch")]
    VersionMismatch = 0x12,

    #[error("Unknown Status Code")]
    Unknown = 0x13,
}

impl From<u8> for StatusCode {
    fn from(code: u8) -> Self {
        match code {
            0x00 => StatusCode::NoError,
            0x01 => StatusCode::PtpSyncLost,
            0x02 => StatusCode::CycleCounterMismatch,
            0x03 => StatusCode::DeadlineMissed,
            0x04 => StatusCode::StreamIdUnknown,
            0x05 => StatusCode::InvalidLen,
            0x06 => StatusCode::AppNotResponding,
            0x07 => StatusCode::PeripheralFault,
            0x08 => StatusCode::NotReady,
            0x09 => StatusCode::AccessDenied,
            0x0A => StatusCode::AuthFailed,
            0x0B => StatusCode::StateConflict,
            0x0C => StatusCode::ParamInvalid,
            0x0D => StatusCode::NoMemory,
            0x0E => StatusCode::NotSupported,
            0x0F => StatusCode::AlreadyRunning,
            0x10 => StatusCode::OsFailure,
            0x11 => StatusCode::IpConflict,
            0x12 => StatusCode::VersionMismatch,
            _ => StatusCode::Unknown,
        }
    }
}
