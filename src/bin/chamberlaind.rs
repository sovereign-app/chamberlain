use std::{
    fs,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use bitcoin::{
    bip32::{ChildNumber, ExtendedPrivKey},
    key::Secp256k1,
    Network,
};
use cdk::{
    mint::Mint,
    nuts::{MintInfo, MintVersion, Nuts},
    secp256k1::{rand::random, PublicKey},
};
use cdk_axum::start_server;
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
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Server, ServerTlsConfig};

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
        let key = ExtendedPrivKey::new_master(config.network, &seed)?;
        let mut file = fs::File::create(&key_file)?;
        file.write_all(&key.encode())?;
    }

    // Generate auth token if necessary
    let auth_token_file = config.data_dir().join(AUTH_TOKEN_FILE);
    if fs::metadata(&auth_token_file).is_err() {
        tracing::info!("Generating auth token");
        let token = random::<[u8; 32]>();
        let mut file = fs::File::create(&auth_token_file)?;
        file.write_all(&token)?;
    }

    // Load key
    let xpriv = ExtendedPrivKey::decode(&fs::read(&key_file)?)?;
    if config.network == Network::Bitcoin && xpriv.network != Network::Bitcoin {
        return Err("Key was not generated for mainnet".into());
    }
    if xpriv.network == Network::Bitcoin && config.network != Network::Bitcoin {
        return Err("Using mainnet key for testing!".into());
    }
    let secp = Secp256k1::new();
    let node_xpriv = xpriv.ckd_priv(&secp, ChildNumber::from_hardened_idx(0)?)?;
    let mint_xpriv = xpriv.ckd_priv(&secp, ChildNumber::from_hardened_idx(1)?)?;

    // Start lightning node
    tracing::info!("Starting lightning node");
    let ln_config = UserConfig {
        accept_forwards_to_priv_channels: true,
        accept_inbound_channels: true,
        channel_handshake_config: ChannelHandshakeConfig {
            minimum_depth: 3,
            negotiate_anchors_zero_fee_htlc_tx: false,
            ..Default::default()
        },
        channel_handshake_limits: ChannelHandshakeLimits {
            force_announced_channel_preference: false,
            their_to_self_delay: 2016,
            max_funding_satoshis: 100_000_000,
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
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            config.lightning_port,
        ))),
    )
    .await?;

    // Start mint
    tracing::info!("Starting mint");
    let mint_store = MintRedbDatabase::new(&config.data_dir().join(MINT_DB_FILE))?;
    let mint = Mint::new(
        config.mint_url.as_str(),
        mint_xpriv.private_key.as_ref(),
        MintInfo {
            name: Some(config.mint_name.clone()),
            pubkey: Some(PublicKey::from_secret_key(&secp, &mint_xpriv.private_key).into()),
            version: Some(MintVersion {
                name: "chamberlain".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }),
            description: Some(config.mint_description.clone()),
            description_long: Some(config.mint_description.clone()),
            contact: None,
            nuts: Nuts::default(),
            motd: None,
        },
        Arc::new(mint_store),
        cdk::Amount::ZERO,
        0.0,
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
            if let Some(identity) = rpc_config.rpc_tls_identity() {
                tracing::info!("Using TLS identity");
                server = server
                    .tls_config(ServerTlsConfig::new().identity(identity))
                    .expect("Invalid TLS config");
            }
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
    let http_addr = SocketAddr::new(config.http_host, config.http_port);
    let http_node = node.clone();
    let http_cancel_token = cancel_token.clone();
    let mint_url = config.mint_url.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = start_server(mint_url.as_str(), http_addr, mint, Arc::new(http_node)) => {}
            _ = http_cancel_token.cancelled() => {}
        }
    });

    // Periodically broadcast node announcement
    if config.lightning_auto_announce
        && config.lightning_announce_addr.ip() != Ipv4Addr::LOCALHOST
        && config.lightning_announce_addr.ip() != Ipv6Addr::LOCALHOST
    {
        let alias = config.mint_name.clone();
        let color = config.mint_color();
        let addrs = vec![config.lightning_announce_addr];
        let announce_node = node.clone();
        let announcement_cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            loop {
                match announce_node.announce_node(&alias, color, addrs.clone()) {
                    Ok(_) => {
                        tracing::debug!("Announced node");
                    }
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
