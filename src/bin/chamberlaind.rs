use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    key::Secp256k1,
    Network, NetworkKind,
};
use cdk::{
    cdk_lightning::MintLightning,
    mint::{FeeReserve, Mint},
    nuts::{CurrencyUnit, MintInfo, MintVersion, Nuts, PaymentMethod},
    secp256k1::rand::random,
    types::{LnKey, QuoteTTL},
};
use cdk_axum::create_mint_router;
use cdk_ldk::{
    lightning::util::config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig},
    BitcoinClient, Node,
};
use cdk_redb::MintRedbDatabase;
use chamberlain::{
    rpc::{chamberlain_server::ChamberlainServer, server_auth_interceptor_from_file},
    server::{Cli, Config, RpcServer, AUTH_TOKEN_FILE, KEY_FILE, MINT_DB_FILE, NODE_DIR},
};
use clap::Parser;
use futures::StreamExt;
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = Config::load(cli);

    // Setup logging and tracing
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_ansi(false)
        .with_env_filter(config.log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    tracing::info!("Starting chamberlaind");
    tracing::debug!("{:?}", config);

    // Create directory if it does not exist
    fs::create_dir_all(config.data_dir())?;

    // Initialize Bitcoin RPC client
    let rpc_client = BitcoinClient::new(
        config.bitcoind_rpc_url.as_str(),
        &config.bitcoind_rpc_user,
        &config.bitcoind_rpc_password,
    )?;

    // Generate key if necessary
    let key_file = config.data_dir().join(KEY_FILE);
    if fs::metadata(&key_file).is_err() {
        tracing::info!("Generating key");
        let seed: [u8; 32] = random();
        let key = Xpriv::new_master(config.network, &seed)?;
        let mut file = fs::File::create(&key_file)?;
        file.write_all(&key.encode())?;
    }

    // Generate auth token if necessary
    let auth_token_file = config.data_dir().join(AUTH_TOKEN_FILE);
    if fs::metadata(&auth_token_file).is_err() {
        tracing::warn!("Generating default auth token");
        let token = [0u8; 32];
        let mut file = fs::File::create(&auth_token_file)?;
        file.write_all(&token)?;
    }

    // Load key
    let xpriv = Xpriv::decode(&fs::read(&key_file)?)?;
    if config.network == Network::Bitcoin && xpriv.network != NetworkKind::Main {
        return Err("Key was not generated for mainnet".into());
    }
    if xpriv.network == NetworkKind::Main && config.network != Network::Bitcoin {
        return Err("Using mainnet key for testing!".into());
    }
    let secp = Secp256k1::new();
    let node_xpriv = xpriv.derive_priv(&secp, &ChildNumber::from_hardened_idx(0)?)?;
    let mint_xpriv = xpriv.derive_priv(&secp, &ChildNumber::from_hardened_idx(1)?)?;

    // Start lightning node
    tracing::info!("Starting lightning node");
    let ln_config = UserConfig {
        accept_forwards_to_priv_channels: true,
        accept_inbound_channels: true,
        channel_handshake_config: ChannelHandshakeConfig {
            minimum_depth: 3,
            our_htlc_minimum_msat: 1000,
            max_inbound_htlc_value_in_flight_percent_of_channel: 100,
            commit_upfront_shutdown_pubkey: false,
            negotiate_anchors_zero_fee_htlc_tx: false,
            our_max_accepted_htlcs: 483,
            ..Default::default()
        },
        channel_handshake_limits: ChannelHandshakeLimits {
            min_funding_satoshis: 1_000_000,
            max_funding_satoshis: 100_000_000,
            force_announced_channel_preference: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let node = Node::start(
        config.data_dir().join(NODE_DIR),
        config.network,
        rpc_client,
        *node_xpriv.private_key.as_ref(),
        ln_config,
        FeeReserve {
            min_fee_reserve: 1.into(),
            percent_fee_reserve: 0.01,
        },
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            config.lightning_port,
        ))),
    )
    .await?;

    // Start mint
    tracing::info!("Starting mint");
    let mint_store = MintRedbDatabase::new(&config.data_dir().join(MINT_DB_FILE))?;
    let mut ln = HashMap::new();
    ln.insert(
        LnKey::new(CurrencyUnit::Sat, PaymentMethod::Bolt11),
        Arc::new(node.clone())
            as Arc<dyn MintLightning<Err = cdk::cdk_lightning::Error> + Send + Sync + 'static>,
    );
    let mint = Mint::new(
        &config.mint_url.to_string(),
        mint_xpriv.private_key.as_ref(),
        MintInfo {
            name: Some(config.mint_name.clone()),
            pubkey: node.get_info().await.ok().map(|i| i.node_id.into()),
            version: Some(MintVersion {
                name: "chamberlain".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }),
            description: Some(config.mint_description.clone()),
            description_long: Some(config.mint_description.clone()),
            contact: config.mint_contact(),
            nuts: Nuts {
                nut04: node.get_mint_settings(),
                nut05: node.get_melt_settings(),
                ..Default::default()
            },
            motd: config.mint_motd(),
            ..Default::default()
        },
        QuoteTTL::new(60, 60),
        Arc::new(mint_store),
        ln,
        vec![(CurrencyUnit::Sat, (0, 64))].into_iter().collect(),
    )
    .await?;

    // Start servers
    let cancel_token = CancellationToken::new();

    tracing::info!("Starting RPC server");
    let rpc_config = config.clone();
    let rpc_node = node.clone();
    let rpc_mint = mint.clone();
    let rpc_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        loop {
            let restart_token = rpc_cancel_token.child_token();
            let rpc_server = RpcServer::new(
                rpc_config.clone(),
                rpc_mint.clone(),
                rpc_node.clone(),
                restart_token.clone(),
            );
            let mut server = Server::builder();
            let svc = ChamberlainServer::with_interceptor(
                rpc_server.clone(),
                server_auth_interceptor_from_file(rpc_config.data_dir().join(AUTH_TOKEN_FILE))
                    .expect("Invalid auth token"),
            );
            let router = server.add_service(svc);
            tokio::select! {
                _ = router.serve(SocketAddr::new(rpc_config.rpc_host, rpc_config.rpc_port)) => {}
                _ = rpc_cancel_token.cancelled() => {}
                _ = restart_token.cancelled() => {}
            }
            if rpc_cancel_token.is_cancelled() {
                break;
            } else {
                tracing::info!("Restarting RPC server");
            }
        }
    });

    tracing::info!("Starting HTTP server");
    let http_config = config.clone();
    let http_mint = mint.clone();
    let http_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        match create_mint_router(Arc::new(http_mint)).await {
            Ok(v1_service) => {
                let addr = SocketAddr::new(http_config.http_host, http_config.http_port);
                if let Err(e) = axum::Server::bind(&addr)
                    .serve(v1_service.into_make_service())
                    .with_graceful_shutdown(async move {
                        http_cancel_token.cancelled().await;
                    })
                    .await
                {
                    tracing::error!("HTTP server error: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to create HTTP server: {}", e);
            }
        }
    });

    // Listen for invoice updates
    let invoice_cancel_token = cancel_token.clone();
    let invoice_mint = mint.clone();
    let invoice_node = node.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = listen_for_invoice_updates(invoice_mint, invoice_node) => {}
            _ = invoice_cancel_token.cancelled() => {}
        }
    });

    // Periodically broadcast node announcement
    if config.lightning_auto_announce {
        let announce_config = config.clone();
        let announce_node = node.clone();
        let announcement_cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            loop {
                let alias = announce_config.mint_name.clone();
                let color = announce_config.mint_color();
                let addrs = match announce_config.lightning_announce_addr.ip() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST) | IpAddr::V6(Ipv6Addr::LOCALHOST) => {
                        if let Some(public_ip) = public_ip::addr().await {
                            vec![SocketAddr::new(public_ip, announce_config.lightning_port)]
                        } else {
                            vec![]
                        }
                    }
                    _ => vec![announce_config.lightning_announce_addr],
                };
                if addrs.is_empty() {
                    tracing::warn!("Public IP not set, skipping node announcement");
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    continue;
                }

                tracing::info!(
                    "Announcing node on {}",
                    addrs
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                );
                match announce_node.announce_node(&alias, color, addrs.clone()) {
                    Ok(_) => {}
                    Err(e) => tracing::error!("Failed to announce node: {}", e),
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
                    _ = announcement_cancel_token.cancelled() => break,

                }
            }
        });
    }
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigint.recv() => tracing::debug!("received SIGINT"),
        _ = sigterm.recv() => tracing::debug!("received SIGTERM"),
    }
    tracing::info!("Shutdown signal received");
    cancel_token.cancel();
    node.stop();
    tracing::info!("Shutdown complete");

    Ok(())
}

async fn listen_for_invoice_updates(
    mint: Mint,
    node: Node,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = node.wait_any_invoice().await?;
    while let Some(request_lookup_id) = stream.next().await {
        tracing::debug!("Invoice with lookup id paid: {}", request_lookup_id);
        if let Ok(Some(mint_quote)) = mint
            .localstore
            .get_mint_quote_by_request_lookup_id(&request_lookup_id)
            .await
        {
            tracing::debug!(
                "Quote {} paid by lookup id {}",
                mint_quote.id,
                request_lookup_id
            );
            mint.localstore
                .update_mint_quote_state(&mint_quote.id, cdk::nuts::MintQuoteState::Paid)
                .await?;
        }
    }
    Ok(())
}
