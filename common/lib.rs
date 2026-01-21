// Re-export the generated gRPC code
pub mod slave_api {
    tonic::include_proto!("slave_api"); // Must match the package name in your .proto file
}

// Existing shared types (Headers, Enums) remain here...
