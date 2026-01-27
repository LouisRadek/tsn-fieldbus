mod discovery_types;
mod l2_types;
mod status_codes;

// Re-export the generated gRPC code
pub mod slave_api {
    tonic::include_proto!("slave_api");
}
