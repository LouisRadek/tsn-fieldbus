//! Slave API client stub for the master.
//!
//! Provides type-safe wrapper around the generated gRPC client and
//! manages token-based authentication for secured endpoints.

use common::slave_api::{
    self, ConfigureStreamsRequest, DeviceStatus, GetDeviceInfoResponse, GetLogRequest,
    GetLogResponse, GetTokenRequest, GetTokenResponse, ProcessDataLayoutResponse,
    SetTargetStateRequest, StatusResponse, StreamConfig, SubscribeStatusRequest,
};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const TOKEN_HEADER_NAME: &str = "token";

#[derive(Clone)]
pub struct SlaveApiClient {
    client: slave_api::slave_api_client::SlaveApiClient<Channel>,
    token: Arc<RwLock<Option<String>>>,
    shared_key: Arc<RwLock<Vec<u8>>>,
}

impl SlaveApiClient {
    pub async fn connect<D>(
        destination: D,
        shared_key: Vec<u8>,
    ) -> Result<Self, tonic::transport::Error>
    where
        D: TryInto<Endpoint>,
        D::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        info!("Connecting to slave API endpoint");
        let client = slave_api::slave_api_client::SlaveApiClient::connect(destination).await?;
        info!("Connected to slave API endpoint");
        Ok(Self {
            client,
            token: Arc::new(RwLock::new(None)),
            shared_key: Arc::new(RwLock::new(shared_key)),
        })
    }

    pub async fn get_token(&mut self) -> Result<GetTokenResponse, Status> {
        let shared_key = self.shared_key.read().await.clone();
        let response = self
            .client
            .get_token(Request::new(GetTokenRequest { shared_key }))
            .await;
        match response {
            Ok(resp) => {
                let inner = resp.into_inner();
                if inner.status == slave_api::StatusCode::NoError as i32 && !inner.token.is_empty()
                {
                    info!("Token acquired successfully");
                    *self.token.write().await = Some(inner.token.clone());
                } else {
                    error!(
                        "Failed to acquire token: status={:?}, token_empty={}",
                        inner.status,
                        inner.token.is_empty()
                    );
                }
                Ok(inner)
            }
            Err(e) => {
                error!("Error while acquiring token: {e}");
                Err(e)
            }
        }
    }

    pub async fn set_target_state(
        &mut self,
        target_state: slave_api::DeviceState,
    ) -> Result<StatusResponse, Status> {
        let request = SetTargetStateRequest {
            target_state: target_state as i32,
        };
        let mut request = Request::new(request);
        self.attach_token(&mut request).await?;
        let response = self.client.set_target_state(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!("Token invalid or expired during set_target_state, refreshing token");
                self.invalidate_token().await;
                let request = SetTargetStateRequest {
                    target_state: target_state as i32,
                };
                let mut request = Request::new(request);
                self.attach_token(&mut request).await?;
                Ok(self.client.set_target_state(request).await?.into_inner())
            }
            Err(status) => {
                error!("set_target_state failed: {status}");
                Err(status)
            }
        }
    }

    pub async fn get_status(&mut self) -> Result<DeviceStatus, Status> {
        let mut request = Request::new(slave_api::Empty {});
        self.attach_token(&mut request).await?;
        let response = self.client.get_status(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!("Token invalid or expired during get_status, refreshing token");
                self.invalidate_token().await;
                let mut request = Request::new(slave_api::Empty {});
                self.attach_token(&mut request).await?;
                Ok(self.client.get_status(request).await?.into_inner())
            }
            Err(status) => {
                error!("get_status failed: {status}");
                Err(status)
            }
        }
    }

    pub async fn subscribe_to_device_status(
        &mut self,
        request: SubscribeStatusRequest,
    ) -> Result<tonic::Streaming<DeviceStatus>, Status> {
        let request_params = request;
        let mut request = Request::new(request_params);
        self.attach_token(&mut request).await?;
        let response = self.client.subscribe_to_device_status(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!(
                    "Token invalid or expired during subscribe_to_device_status, refreshing token"
                );
                self.invalidate_token().await;
                let mut request = Request::new(request_params);
                self.attach_token(&mut request).await?;
                Ok(self
                    .client
                    .subscribe_to_device_status(request)
                    .await?
                    .into_inner())
            }
            Err(status) => {
                error!("subscribe_to_device_status failed: {status}");
                Err(status)
            }
        }
    }

    pub async fn get_device_status_log(
        &mut self,
        offset: u32,
        limit: u32,
    ) -> Result<GetLogResponse, Status> {
        let mut request = Request::new(GetLogRequest { offset, limit });
        self.attach_token(&mut request).await?;
        let response = self.client.get_device_status_log(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!("Token invalid or expired during get_device_status_log, refreshing token");
                self.invalidate_token().await;
                let mut request = Request::new(GetLogRequest { offset, limit });
                self.attach_token(&mut request).await?;
                Ok(self
                    .client
                    .get_device_status_log(request)
                    .await?
                    .into_inner())
            }
            Err(status) => {
                error!("get_device_status_log failed: {status}");
                Err(status)
            }
        }
    }

    pub async fn get_device_info(&mut self) -> Result<GetDeviceInfoResponse, Status> {
        let mut request = Request::new(slave_api::Empty {});
        self.attach_token(&mut request).await?;
        let response = self.client.get_device_info(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!("Token invalid or expired during get_device_info, refreshing token");
                self.invalidate_token().await;
                let mut request = Request::new(slave_api::Empty {});
                self.attach_token(&mut request).await?;
                Ok(self.client.get_device_info(request).await?.into_inner())
            }
            Err(status) => {
                error!("get_device_info failed: {status}");
                Err(status)
            }
        }
    }

    pub async fn get_process_data_layout(&mut self) -> Result<ProcessDataLayoutResponse, Status> {
        let mut request = Request::new(slave_api::Empty {});
        self.attach_token(&mut request).await?;
        let response = self.client.get_process_data_layout(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!("Token invalid or expired during get_process_data_layout, refreshing token");
                self.invalidate_token().await;
                let mut request = Request::new(slave_api::Empty {});
                self.attach_token(&mut request).await?;
                Ok(self
                    .client
                    .get_process_data_layout(request)
                    .await?
                    .into_inner())
            }
            Err(status) => {
                error!("get_process_data_layout failed: {status}");
                Err(status)
            }
        }
    }

    pub async fn reset_sequence_number(&mut self) -> Result<StatusResponse, Status> {
        let mut request = Request::new(slave_api::Empty {});
        self.attach_token(&mut request).await?;
        let response = self.client.reset_sequence_number(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!("Token invalid or expired during reset_sequence_number, refreshing token");
                self.invalidate_token().await;
                let mut request = Request::new(slave_api::Empty {});
                self.attach_token(&mut request).await?;
                Ok(self
                    .client
                    .reset_sequence_number(request)
                    .await?
                    .into_inner())
            }
            Err(status) => {
                error!("reset_sequence_number failed: {status}");
                Err(status)
            }
        }
    }

    pub async fn configure_streams(
        &mut self,
        streams: Vec<StreamConfig>,
    ) -> Result<StatusResponse, Status> {
        let mut request = Request::new(ConfigureStreamsRequest {
            streams: streams.clone(),
        });
        self.attach_token(&mut request).await?;
        let response = self.client.configure_streams(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!("Token invalid or expired during configure_streams, refreshing token");
                self.invalidate_token().await;
                let mut request = Request::new(ConfigureStreamsRequest { streams });
                self.attach_token(&mut request).await?;
                Ok(self.client.configure_streams(request).await?.into_inner())
            }
            Err(status) => {
                error!("configure_streams failed: {status}");
                Err(status)
            }
        }
    }

    async fn attach_token<T>(&mut self, request: &mut Request<T>) -> Result<(), Status> {
        self.ensure_token().await?;
        let token = self.token.read().await.clone().ok_or_else(|| {
            error!("Missing authentication token when attaching to request");
            Status::unauthenticated("missing authentication token")
        })?;
        let header_value = token.parse().map_err(|_| {
            error!("Invalid token format when attaching to request");
            Status::internal("invalid token format")
        })?;
        request
            .metadata_mut()
            .insert(TOKEN_HEADER_NAME, header_value);
        Ok(())
    }

    async fn ensure_token(&mut self) -> Result<(), Status> {
        if self.token.read().await.is_some() {
            return Ok(());
        }
        warn!("No authentication token present, refreshing token");
        self.refresh_token().await
    }

    async fn refresh_token(&mut self) -> Result<(), Status> {
        let response = self.get_token().await?;
        if response.status != slave_api::StatusCode::NoError as i32 || response.token.is_empty() {
            error!(
                "Token refresh failed: status={:?}, token_empty={}",
                response.status,
                response.token.is_empty()
            );
            return Err(Status::unauthenticated("token refresh failed"));
        }
        Ok(())
    }

    async fn invalidate_token(&self) {
        warn!("Invalidating authentication token");
        *self.token.write().await = None;
    }
}
