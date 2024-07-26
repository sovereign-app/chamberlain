#[cfg(feature = "server")]
pub mod server;

pub mod rpc {
    use std::{
        collections::HashSet,
        fs, io,
        path::Path,
        str::FromStr,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use base64::engine::{general_purpose, Engine};
    use fast_socks5::{
        client::{Config, Socks5Stream},
        SocksError,
    };
    use hmac::{Hmac, Mac};
    use hyper_util::rt::TokioIo;
    use sha2::Sha256;
    use spake2::{Ed25519Group, Identity, Password, Spake2};
    use subtle::ConstantTimeEq;
    use tokio::net::lookup_host;
    use tonic::{
        transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Uri},
        Request, Status,
    };
    use tower::service_fn;
    use url::Url;
    use uuid::Uuid;

    const AUTHORIZATION_HEADER: &str = "authorization";
    const HMAC_PREFIX: &str = "HMAC-SHA256 ";
    const REQUEST_ID_HEADER: &str = "request-id";

    tonic::include_proto!("chamberlain");

    pub async fn create_channel<P: AsRef<Path>>(
        addr: Url,
        proxy: Option<Url>,
        ca_file: Option<P>,
    ) -> Result<Channel, Box<dyn std::error::Error>> {
        let proxy_addr = if let Some(proxy) = proxy {
            if !proxy.scheme().starts_with("socks5") {
                return Err("Invalid proxy scheme".into());
            }
            let host = proxy.host_str().ok_or("Invalid host")?;
            let port = proxy.port().ok_or("Invalid port")?;
            let mut addrs = lookup_host(format!("{}:{}", host, port)).await?;
            Some(addrs.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "No addresses found")
            })?)
        } else {
            None
        };
        let mut endpoint = Endpoint::from_shared(addr.to_string())?;
        if addr.scheme() == "https" {
            let mut tls_config = ClientTlsConfig::new();
            if let Some(ca_file) = ca_file {
                tls_config = tls_config.ca_certificate(Certificate::from_pem(&fs::read(ca_file)?));
            }
            endpoint = endpoint.tls_config(tls_config)?;
        }
        let channel = match proxy_addr {
            Some(proxy_addr) => {
                endpoint
                    .connect_with_connector(service_fn(move |uri: Uri| async move {
                        let host = uri.host().ok_or(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Invalid URI host",
                        ))?;
                        let port = uri.port_u16().unwrap_or(80);
                        Ok::<_, io::Error>(TokioIo::new(
                            Socks5Stream::connect(
                                proxy_addr,
                                host.to_string(),
                                port,
                                Config::default(),
                            )
                            .await
                            .map_err(|e| match e {
                                SocksError::Io(e) => e,
                                _ => io::Error::new(io::ErrorKind::Other, e),
                            })?
                            .get_socket(),
                        ))
                    }))
                    .await?
            }
            None => endpoint.connect().await?,
        };
        Ok(channel)
    }

    pub fn client_auth_interceptor(
        token: &[u8],
    ) -> Result<impl FnMut(Request<()>) -> Result<Request<()>, Status>, Box<dyn std::error::Error>>
    {
        let token = token.to_vec();
        Ok(move |mut req: Request<()>| {
            // Generate request id
            let request_id = Uuid::now_v7();

            // Insert timestamp into headers
            req.metadata_mut().insert(
                REQUEST_ID_HEADER,
                request_id
                    .to_string()
                    .parse()
                    .map_err(|_| Status::invalid_argument("Invalid request id"))?,
            );

            // Create HMAC-SHA256 signature
            let mut mac = Hmac::<Sha256>::new_from_slice(&token)
                .map_err(|e| Status::internal(e.to_string()))?;
            mac.update(request_id.as_bytes());
            let signature = mac.finalize().into_bytes();

            // Set the authorization header
            let auth_header_value = format!(
                "{}{}",
                HMAC_PREFIX,
                general_purpose::STANDARD.encode(signature)
            )
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid auth header"))?;
            req.metadata_mut()
                .insert(AUTHORIZATION_HEADER, auth_header_value);

            Ok(req)
        })
    }

    pub fn client_auth_interceptor_from_file<P>(
        path: P,
    ) -> Result<impl FnMut(Request<()>) -> Result<Request<()>, Status>, Box<dyn std::error::Error>>
    where
        P: AsRef<Path>,
    {
        let token = std::fs::read(path)?;
        client_auth_interceptor(&token)
    }

    pub fn server_auth_interceptor(
        token: &[u8],
    ) -> Result<
        impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone,
        Box<dyn std::error::Error>,
    > {
        let token: Vec<u8> = token.to_vec();
        let request_ids = Arc::new(Mutex::new(HashSet::<Uuid>::new()));
        Ok(move |req: Request<()>| {
            // Extract the authorization header
            let auth_header = match req.metadata().get(AUTHORIZATION_HEADER) {
                Some(val) => val
                    .to_str()
                    .map_err(|_| Status::unauthenticated("Invalid auth header"))?,
                None => return Err(Status::unauthenticated("Missing auth header")),
            };

            // Parse the authorization header to extract the signature
            let request_signature = general_purpose::STANDARD
                .decode(
                    auth_header
                        .strip_prefix(HMAC_PREFIX)
                        .ok_or_else(|| Status::unauthenticated("Invalid auth header"))?,
                )
                .map_err(|_| Status::unauthenticated("Invalid auth header"))?;

            // Extract request id
            let request_id = match req.metadata().get("request-id") {
                Some(val) => Uuid::from_str(
                    val.to_str()
                        .map_err(|_| Status::unauthenticated("Invalid request id"))?,
                )
                .map_err(|_| Status::unauthenticated("Invalid request id"))?,
                None => return Err(Status::unauthenticated("Missing request id")),
            };

            // Check request id timetamp
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Status::internal(e.to_string()))?;
            let request_timestamp = request_id
                .get_timestamp()
                .ok_or_else(|| Status::unauthenticated("Invalid request id"))?;
            if (current_time.as_secs() as i64 - request_timestamp.to_unix().0 as i64).abs() > 60 {
                return Err(Status::unauthenticated("Request id expired"));
            }

            // Compute HMAC-SHA256 signature
            let mut mac = Hmac::<Sha256>::new_from_slice(&token)
                .map_err(|_| Status::internal("Invalid token"))?;
            mac.update(request_id.as_bytes());
            let result = mac.finalize();

            // Compare the computed HMAC signature with the one from the header
            if result.into_bytes().ct_eq(&request_signature).unwrap_u8() != 1 {
                return Err(Status::unauthenticated("Invalid signature"));
            }

            // Check if request id has already been used
            let mut request_ids = request_ids
                .lock()
                .map_err(|_| Status::internal("Mutex error"))?;
            if request_ids.contains(&request_id) {
                return Err(Status::unauthenticated("Request id already used"));
            }
            request_ids.insert(request_id);

            // Filter old request ids
            if request_ids.len() > 100 {
                request_ids.retain(|id| match id.get_timestamp() {
                    None => false,
                    Some(timestamp) => {
                        (current_time.as_secs() as i64 - timestamp.to_unix().0 as i64).abs() < 60
                    }
                });
            }
            drop(request_ids);

            Ok(req)
        })
    }

    pub fn server_auth_interceptor_from_file<P>(
        path: P,
    ) -> Result<
        impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone,
        Box<dyn std::error::Error>,
    >
    where
        P: AsRef<Path>,
    {
        let token = std::fs::read(path)?;
        server_auth_interceptor(&token)
    }

    pub fn start_auth_token(password: &str) -> (Spake2<Ed25519Group>, Vec<u8>) {
        Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(password),
            &Identity::new(b"chamberlain"),
        )
    }

    pub fn finish_auth_token(
        s: Spake2<Ed25519Group>,
        m: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(s.finish(&m).map_err(|e| e.to_string())?)
    }

    pub fn finish_auth_token_base64(
        s: Spake2<Ed25519Group>,
        m: Vec<u8>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Ok(general_purpose::STANDARD.encode(finish_auth_token(s, m)?))
    }
}
