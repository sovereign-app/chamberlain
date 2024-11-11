#[cfg(feature = "server")]
pub mod server;

pub mod rpc {
    tonic::include_proto!("chamberlain");
}
