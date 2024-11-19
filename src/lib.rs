#[cfg(feature = "server")]
pub mod server;

pub mod rpc {
    use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
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
        validation.algorithms = vec![Algorithm::RS256];
        let keys = jwk_set
            .keys
            .into_iter()
            .map(|key| DecodingKey::from_jwk(&key))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(move |req: Request<()>| {
            if let Some(value) = req.metadata().get("authorization") {
                let token = value
                    .to_str()
                    .map_err(|e| Status::invalid_argument(format!("Token Error: {}", e)))?
                    .strip_prefix("Bearer ")
                    .ok_or_else(|| Status::invalid_argument("Invalid token"))?;
                for key in &keys {
                    if let Ok(token_data) = jsonwebtoken::decode::<Claims>(token, key, &validation)
                    {
                        if token_data.claims.sub != sub {
                            return Err(Status::unauthenticated("Invalid token"));
                        }
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
