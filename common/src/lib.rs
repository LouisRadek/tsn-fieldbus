pub mod discovery_types;
pub mod hardware_abstraction;
pub mod l2_types;
pub mod l2_utils;
pub mod status_codes;
pub mod stream_store;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_mocks;

// Re-export the generated gRPC code
pub mod slave_api {
    tonic::include_proto!("slave_api");
}
