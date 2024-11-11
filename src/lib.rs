#[cfg(feature = "server")]
pub mod server;

pub mod rpc {
    use jsonwebtoken::{jwk::JwkSet, DecodingKey, Validation};
    use tonic::{
        metadata::{errors::InvalidMetadataValue, MetadataValue},
        Request, Status,
    };

    tonic::include_proto!("chamberlain");

    pub fn client_auth_interceptor(
        token: String,
    ) -> Result<impl FnMut(Request<()>) -> Result<Request<()>, Status>, InvalidMetadataValue> {
        let bearer_token = format!("Bearer {}", token);
        let header_value: MetadataValue<_> = bearer_token.parse()?;
        Ok(move |mut req: Request<()>| {
            req.metadata_mut()
                .insert("authorization", header_value.clone());
            Ok(req)
        })
    }

    pub fn server_auth_interceptor(
        sub: String,
        jwk_set: JwkSet,
    ) -> Result<
        impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone,
        Box<dyn std::error::Error>,
    > {
        let mut validation = Validation::default();
        validation.sub = Some(sub);
        let keys = jwk_set
            .keys
            .into_iter()
            .map(|key| DecodingKey::from_jwk(&key))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(move |req: Request<()>| {
            if let Some(value) = req.metadata().get("authorization") {
                for key in &keys {
                    if let Ok(token) = jsonwebtoken::decode::<Claims>(
                        value
                            .to_str()
                            .map_err(|e| Status::invalid_argument(format!("token error: {}", e)))?,
                        key,
                        &validation,
                    ) {
                        tracing::debug!("Authenticated as {}", token.claims.sub);
                        return Ok(req);
                    }
                }
                Err(Status::unauthenticated("Invalid token"))
            } else {
                Err(Status::unauthenticated("Missing token"))
            }
        })
    }

    #[derive(Debug, serde::Deserialize)]
    struct Claims {
        sub: String,
    }
}
