#[cfg(feature = "server")]
pub mod server;

pub mod rpc {
    use std::{
        collections::HashSet,
        path::Path,
        str::FromStr,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use base64::engine::{general_purpose, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use spake2::{Ed25519Group, Identity, Password, Spake2};
    use subtle::ConstantTimeEq;
    use tonic::{Request, Status};
    use uuid::Uuid;

    const AUTHORIZATION_HEADER: &str = "authorization";
    const HMAC_PREFIX: &str = "HMAC-SHA256 ";
    const REQUEST_ID_HEADER: &str = "request-id";

    tonic::include_proto!("chamberlain");

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
