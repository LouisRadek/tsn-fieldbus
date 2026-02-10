//! Slave API gRPC service implementation.
//!
//! This module implements the gRPC endpoints for managing and monitoring a
//! slave device. It adapts the generated `common::slave_api` service definition
//! to the runtime primitives of the slave (device info access, process image
//! access, state manager, status store and token store).
//!
//! Authentication:
//! - `get_token` issues time-limited tokens when a correct pre-shared key is
//!   presented. Other RPCs require the token to be supplied in the request
//!   metadata header named `token`.

use common::hardware_abstraction::{DeviceInfoAccess, ProcessImageAccess};
use common::slave_api::{
    self, ConfigureStreamsRequest, DeviceState, DeviceStatus, Direction, GetDeviceInfoResponse,
    GetLogRequest, GetLogResponse, GetTokenRequest, GetTokenResponse, ProcessDataLayoutResponse,
    ProcessVariable, StatusCode, StatusResponse, StreamConfig, SubscribeStatusRequest,
};
use common::state_machine::DeviceStateManager;
use common::stream_store::StreamStore;
use log::{debug, info};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{DeviceStatusStore, TokenStore};

const TOKEN_HEADER_NAME: &str = "token";
const TOKEN_TTL_SECONDS: u64 = 600;
const MIN_INTERVAL_SEC_STATUS_PUBLISH: u32 = 60;
const MIN_CYCLE_TIME_NS: u32 = 250000;

/// Start the gRPC server and serve the `SlaveApi` implementation at `address`.
///
/// # Errors
///
/// Returns an error if the server cannot bind to the address or the service
/// fails to start.
pub async fn start_slave_api_server(
    address: SocketAddr,
    device_info_access: Arc<dyn DeviceInfoAccess>,
    process_image_access: Arc<dyn ProcessImageAccess>,
    state_manager: DeviceStateManager,
    status_store: DeviceStatusStore,
    token_store: TokenStore,
    stream_store: StreamStore,
) -> Result<(), tonic::transport::Error> {
    let service = SlaveApiService::new(
        device_info_access,
        process_image_access,
        state_manager,
        status_store,
        token_store,
        stream_store,
    );

    info!("Starting Slave API server on {address}");

    tonic::transport::Server::builder()
        .add_service(slave_api::slave_api_server::SlaveApiServer::new(service))
        .serve(address)
        .await
}

#[derive(Clone)]
struct SlaveApiService {
    device_info_access: Arc<dyn DeviceInfoAccess>,
    process_image_access: Arc<dyn ProcessImageAccess>,
    state_manager: DeviceStateManager,
    status_store: DeviceStatusStore,
    token_store: TokenStore,
    stream_store: StreamStore,
}

impl SlaveApiService {
    fn new(
        device_info_access: Arc<dyn DeviceInfoAccess>,
        process_image_access: Arc<dyn ProcessImageAccess>,
        state_manager: DeviceStateManager,
        status_store: DeviceStatusStore,
        token_store: TokenStore,
        stream_store: StreamStore,
    ) -> Self {
        Self {
            device_info_access,
            process_image_access,
            state_manager,
            status_store,
            token_store,
            stream_store,
        }
    }

    #[allow(clippy::result_large_err)]
    fn validate_token<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let provided = request
            .metadata()
            .get(TOKEN_HEADER_NAME)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        let Some(token) = provided else {
            return Err(Status::unauthenticated("missing or invalid token"));
        };

        if self.token_store.validate_token(&token) {
            Ok(())
        } else {
            Err(Status::unauthenticated("missing or invalid token"))
        }
    }
}

/// gRPC methods exposed by the slave.
///
/// The implementations validate the request token and then delegate to the
/// runtime components. Each RPC produces a typed response defined in the
/// `common::slave_api` proto definitions.
#[tonic::async_trait]
impl slave_api::slave_api_server::SlaveApi for SlaveApiService {
    async fn set_target_state(
        &self,
        request: Request<slave_api::SetTargetStateRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        self.validate_token(&request)?;
        let target_state = request.into_inner().target_state();

        match self.state_manager.set_target_state(target_state) {
            Ok(()) => {
                self.status_store.update_state(target_state).await;
                Ok(Response::new(StatusResponse {
                    code: StatusCode::NoError as i32,
                }))
            }
            Err(code) => Ok(Response::new(StatusResponse { code: code as i32 })),
        }
    }

    async fn get_status(
        &self,
        request: Request<slave_api::Empty>,
    ) -> Result<Response<DeviceStatus>, Status> {
        self.validate_token(&request)?;
        let status = self.status_store.get_status().await;
        Ok(Response::new(status))
    }

    type SubscribeToDeviceStatusStream = ReceiverStream<Result<DeviceStatus, Status>>;

    async fn subscribe_to_device_status(
        &self,
        request: Request<SubscribeStatusRequest>,
    ) -> Result<Response<Self::SubscribeToDeviceStatusStream>, Status> {
        self.validate_token(&request)?;
        let params = request.into_inner();
        let mut receiver = self.status_store.subscribe();
        let (sender, stream_receiver) = tokio::sync::mpsc::channel(32);
        let status_store = self.status_store.clone();

        tokio::spawn(async move {
            let mut interval = if let Some(mut min_interval_sec) = params.min_interval_sec {
                if min_interval_sec < 10 {
                    min_interval_sec = MIN_INTERVAL_SEC_STATUS_PUBLISH;
                }
                Some(tokio::time::interval(Duration::from_secs(
                    min_interval_sec as u64,
                )))
            } else {
                None
            };

            loop {
                tokio::select! {
                    message = receiver.recv() => {
                        match message {
                            Ok(status) => {
                                if sender.send(Ok(status)).await.is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(count)) => {
                                debug!("Subscriber lagged by {count} messages");
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = async {
                        if let Some(ref mut interval) = interval {
                            interval.tick().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        let status = status_store.get_status().await;
                        if sender.send(Ok(status)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(stream_receiver)))
    }

    async fn get_device_status_log(
        &self,
        request: Request<GetLogRequest>,
    ) -> Result<Response<GetLogResponse>, Status> {
        self.validate_token(&request)?;
        let params = request.into_inner();
        let limit = params.limit.min(30) as usize;
        let offset = params.offset as usize;
        let (total, entries) = self.status_store.get_log(offset, limit);

        Ok(Response::new(GetLogResponse {
            total_entries: total,
            log_entries: entries,
        }))
    }

    async fn get_device_info(
        &self,
        request: Request<slave_api::Empty>,
    ) -> Result<Response<GetDeviceInfoResponse>, Status> {
        self.validate_token(&request)?;
        let info = match self.device_info_access.read_device_info() {
            Ok(info) => info,
            Err(code) => {
                return Ok(Response::new(GetDeviceInfoResponse {
                    code: code as i32,
                    device_info: None,
                }));
            }
        };
        Ok(Response::new(GetDeviceInfoResponse {
            code: StatusCode::NoError as i32,
            device_info: Some(info),
        }))
    }

    async fn get_process_data_layout(
        &self,
        request: Request<slave_api::Empty>,
    ) -> Result<Response<ProcessDataLayoutResponse>, Status> {
        self.validate_token(&request)?;
        let variables = match self.process_image_access.get_layout() {
            Ok(layout) => layout,
            Err(code) => {
                return Ok(Response::new(ProcessDataLayoutResponse {
                    code: code as i32,
                    variables: vec![],
                }));
            }
        };
        Ok(Response::new(ProcessDataLayoutResponse {
            code: StatusCode::NoError as i32,
            variables,
        }))
    }

    async fn configure_streams(
        &self,
        request: Request<ConfigureStreamsRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        self.validate_token(&request)?;

        if self.state_manager.get_state() != DeviceState::PreOp {
            return Ok(Response::new(StatusResponse {
                code: StatusCode::ErrNotReady as i32,
            }));
        }

        let request = request.into_inner();
        let layout = match self.process_image_access.get_layout() {
            Ok(layout) => layout,
            Err(code) => return Ok(Response::new(StatusResponse { code: code as i32 })),
        };

        if let Err(code) = validate_streams(&request.streams, &layout) {
            return Ok(Response::new(StatusResponse { code: code as i32 }));
        }

        self.stream_store.reset();
        if let Err(code) = self.stream_store.add_stream_configs(request.streams) {
            return Ok(Response::new(StatusResponse { code: code as i32 }));
        }

        Ok(Response::new(StatusResponse {
            code: StatusCode::NoError as i32,
        }))
    }

    async fn get_token(
        &self,
        request: Request<GetTokenRequest>,
    ) -> Result<Response<GetTokenResponse>, Status> {
        let shared_key = request.into_inner().shared_key;

        let token = match self
            .token_store
            .issue_token(&shared_key, Duration::from_secs(TOKEN_TTL_SECONDS))
        {
            Ok(token) => {
                info!("Issued new authentication token");
                token
            }
            Err(status_code) => {
                return Ok(Response::new(GetTokenResponse {
                    token: String::new(),
                    status: status_code as i32,
                }));
            }
        };

        Ok(Response::new(GetTokenResponse {
            token,
            status: StatusCode::NoError as i32,
        }))
    }

    async fn reset_sequence_number(
        &self,
        request: Request<slave_api::Empty>,
    ) -> Result<Response<StatusResponse>, Status> {
        self.validate_token(&request)?;

        // TODO: Add reset of the sequence number of the discovery and L2 protocol security

        Ok(Response::new(StatusResponse {
            code: StatusCode::ErrNotSupported as i32,
        }))
    }
}

fn validate_streams(
    streams: &[StreamConfig],
    layout: &[ProcessVariable],
) -> Result<(), StatusCode> {
    let mut seen_stream_ids = HashSet::new();

    for stream in streams {
        if stream.stream_id > u16::MAX as u32 {
            return Err(StatusCode::ErrParamInvalid);
        }
        if !seen_stream_ids.insert(stream.stream_id) {
            return Err(StatusCode::ErrParamInvalid);
        }
        if stream.destination_mac.len() != 6 {
            return Err(StatusCode::ErrParamInvalid);
        }
        if stream.cycle_time_nano < MIN_CYCLE_TIME_NS {
            return Err(StatusCode::ErrParamInvalid);
        }
        let content = stream
            .stream_content
            .as_ref()
            .ok_or(StatusCode::ErrParamInvalid)?;

        if content.bit_len == 0 {
            return Err(StatusCode::ErrParamInvalid);
        }

        let direction =
            Direction::try_from(stream.direction).map_err(|_| StatusCode::ErrParamInvalid)?;

        let matches = layout.iter().any(|variable| {
            variable.direction == direction as i32
                && variable.byte_offset == content.byte_offset
                && variable.bit_offset == content.bit_offset
                && variable.bit_len == content.bit_len
        });

        if !matches {
            return Err(StatusCode::ErrParamInvalid);
        }
    }

    Ok(())
}
