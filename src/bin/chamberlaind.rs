use std::{
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
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
use cdk_ldk::{BitcoinClient, Node};
use cdk_redb::MintRedbDatabase;
use chamberlain::{
    rpc::chamberlain_server::ChamberlainServer,
    server::{Cli, Config, RpcServer, KEY_FILE, MINT_DB_FILE, NODE_DIR},
};
use clap::Parser;
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
    let rpc_configent = BitcoinClient::new(
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
    let node = Node::start(
        config.data_dir().join(NODE_DIR),
        config.network,
        rpc_configent,
        *node_xpriv.private_key.as_ref(),
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            config.lightning_port,
        ))),
    )
    .await?;

    // Start mint
    tracing::info!("Starting mint");
    let mint_store = MintRedbDatabase::new(
        config
            .data_dir()
            .join(MINT_DB_FILE)
            .to_str()
            .ok_or("mint directory error")?,
    )?;
    let mint = Mint::new(
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
    let rpc_addr = SocketAddr::new(config.rpc_host, config.rpc_port);
    let rpc_server = RpcServer::new(config.clone(), mint.clone(), node.clone());
    let rpc_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        let server = Server::builder().add_service(ChamberlainServer::new(rpc_server));
        tokio::select! {
            _ = server.serve(rpc_addr) => {}
            _ = rpc_cancel_token.cancelled() => {}
        }
    });

    tracing::info!("Starting HTTP server");
    let http_addr = SocketAddr::new(config.http_host, config.http_port);
    let http_node = node.clone();
    let http_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = start_server(config.mint_url.as_str(), http_addr, mint, Arc::new(http_node)) => {}
            _ = http_cancel_token.cancelled() => {}
        }
    });

    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigint.recv() => tracing::debug!("received SIGINT"),
        _ = sigterm.recv() => tracing::debug!("received SIGTERM"),
    }
    tracing::info!("Shutdown signal received");
    cancel_token.cancel();
    node.stop();

    Ok(())
}
