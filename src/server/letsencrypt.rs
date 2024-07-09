use std::{
    collections::HashMap,
    fs::{self, File},
    path::PathBuf,
    time::Duration,
};

use bitcoin::Network;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};

use crate::rpc::OrderCertificateResponse;

use super::{Config, TLS_CERT_FILE, TLS_DIR, TLS_KEY_FILE, TLS_LET_ENCRYPT_CRED_FILE};

pub async fn order_certificate(
    config: &Config,
    domains: Vec<String>,
) -> Result<OrderCertificateResponse, Box<dyn std::error::Error>> {
    // Create new order
    let account = create_or_load_account(config).await?;
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &domains
                .iter()
                .map(|d| Identifier::Dns(d.clone()))
                .collect::<Vec<_>>(),
        })
        .await?;

    // Check authorizations
    let authorizations = order.authorizations().await?;
    let mut challenge_urls = Vec::new();
    let mut challenge_records = HashMap::new();
    for auth in authorizations {
        match auth.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            status => return Err(format!("Authorization failed: {:?}", status).into()),
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| "no dns01 challenge found")?;
        let Identifier::Dns(identifier) = &auth.identifier;
        challenge_urls.push(challenge.url.clone());
        challenge_records.insert(
            identifier.clone(),
            order.key_authorization(challenge).dns_value(),
        );
    }

    Ok(OrderCertificateResponse {
        order_url: order.url().to_string(),
        challenge_records,
        challenge_urls,
    })
}

pub async fn provision_certificate(
    config: &Config,
    order_url: String,
    challenge_urls: Vec<String>,
    domains: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load order
    let account = create_or_load_account(config).await?;
    let mut order = account.order(order_url).await?;

    // Set challenges ready
    for url in challenge_urls {
        order.set_challenge_ready(&url).await?;
    }

    // Check order state
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        tokio::time::sleep(delay).await;
        let state = order.refresh().await?;
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            tracing::info!("SSL cert order state: {:#?}", state);
            break;
        }

        delay *= 2;
        tries += 1;
        match tries < 5 {
            true => tracing::info!(
                ?state,
                tries,
                "SSL cert order is not ready, waiting {delay:?}"
            ),
            false => {
                tracing::error!(tries, "SSL cert order is not ready: {state:#?}");
                return Err("SSL cert order is not ready after timeout".into());
            }
        }
    }

    if order.state().status != OrderStatus::Ready {
        return Err(format!("unexpected order status: {:?}", order.state().status).into());
    }

    // Create certificate signing request
    let mut params = CertificateParams::new(domains)?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate()?;
    let csr = params.serialize_request(&key_pair)?;

    // Finalize the order and save certificate chain and private key
    order.finalize(csr.der()).await?;
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    };
    fs::write(tls_dir(&config).join(TLS_CERT_FILE), cert_chain_pem)?;
    fs::write(
        tls_dir(&config).join(TLS_KEY_FILE),
        key_pair.serialize_pem(),
    )?;

    Ok(())
}

async fn create_or_load_account(config: &Config) -> Result<Account, Box<dyn std::error::Error>> {
    let credentials_file = tls_dir(config).join(TLS_LET_ENCRYPT_CRED_FILE);
    let account = if fs::metadata(&credentials_file).is_err() {
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            if config.network == Network::Bitcoin {
                LetsEncrypt::Production.url()
            } else {
                LetsEncrypt::Staging.url()
            },
            None,
        )
        .await?;
        serde_json::to_writer(File::create(credentials_file)?, &credentials)?;
        account
    } else {
        let credentials: AccountCredentials =
            serde_json::from_reader(File::open(credentials_file)?)?;
        Account::from_credentials(credentials).await?
    };

    Ok(account)
}

fn tls_dir(config: &Config) -> PathBuf {
    config.data_dir().join(TLS_DIR)
}
