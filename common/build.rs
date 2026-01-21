use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc_path = protobuf_src::protoc();

    unsafe { env::set_var("PROTOC", protoc_path) };

    tonic_build::compile_protos("proto/slave-api.proto")?;

    Ok(())
}
