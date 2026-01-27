pub mod discovery_types;
pub mod l2_types;
pub mod status_codes;

// Re-export the generated gRPC code
pub mod slave_api {
    tonic::include_proto!("slave_api");
}
