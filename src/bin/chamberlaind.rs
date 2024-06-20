use std::{
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
};

use bitcoin::{
    bip32::{ChildNumber, ExtendedPrivKey},
    key::Secp256k1,
    Network,
};
use cdk::{mint::Mint, nuts::MintInfo, secp256k1::rand::random, Amount};
use cdk_axum::start_server;
use cdk_ldk::{BitcoinClient, Node};
use cdk_redb::MintRedbDatabase;
use clap::Parser;
use tracing::level_filters::LevelFilter;
use url::Url;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Network
    #[arg(long, default_value = "regtest")]
    network: Network,

    /// Lightning network port
    #[arg(long, value_name = "PORT", default_value = "9735")]
    lightning_port: u16,

    /// Host IP to bind the RPC server
    #[arg(long, value_name = "HOST", default_value = "127.0.0.1")]
    rpc_host: IpAddr,

    /// Port to bind the RPC server
    #[arg(long, value_name = "PORT", default_value = "3339")]
    rpc_port: u16,

    /// Host IP to bind the HTTP server
    #[arg(long, value_name = "HOST", default_value = "127.0.0.1")]
    http_host: IpAddr,

    /// Port to bind the HTTP server
    #[arg(long, value_name = "PORT", default_value = "3338")]
    http_port: u16,

    /// Data directory
    #[arg(long, value_name = "DIR", default_value = "~/.chamberlain")]
    data_dir: PathBuf,

    /// Bitcoind RPC url
    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:8332")]
    bitcoind_rpc_url: Url,

    /// Bitcoind RPC user
    #[arg(long, value_name = "USER", default_value = "user")]
    bitcoind_rpc_user: String,

    /// Bitcoind RPC password
    #[arg(long, value_name = "PASSWORD", default_value = "password")]
    bitcoind_rpc_password: String,

    /// Mint URL
    #[arg(long, value_name = "URL", default_value = "http://localhost:3338")]
    mint_url: Url,

    /// Log level
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: LevelFilter,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Setup logging and tracing
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(cli.log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    tracing::debug!("{:?}", cli);
    tracing::info!("Starting chamberlaind");

    // Create directory if it does not exist
    let data_dir = if let Some(home_dir) = dirs::home_dir() {
        if let Ok(without_tilde) = cli.data_dir.strip_prefix("~") {
            home_dir.join(without_tilde)
        } else {
            cli.data_dir.clone()
        }
    } else {
        cli.data_dir.clone()
    };
    fs::create_dir_all(&data_dir)?;

    // Initialize Bitcoin RPC client
    let rpc_client = BitcoinClient::new(
        cli.bitcoind_rpc_url.as_str(),
        &cli.bitcoind_rpc_user,
        &cli.bitcoind_rpc_password,
    )?;

    // Load or generate seed for xprivs
    let seed_file_path = data_dir.join("seed");
    tracing::debug!("Seed file path: {:?}", seed_file_path);
    let seed = if fs::metadata(&seed_file_path).is_ok() {
        tracing::info!("Loading seed from file");
        fs::read(seed_file_path)?
    } else {
        tracing::info!("Generating new seed");
        let new_seed: [u8; 32] = random();
        let mut file = fs::File::create(&seed_file_path)?;
        file.write_all(&new_seed)?;
        new_seed.to_vec()
    };
    let secp = Secp256k1::new();
    let xpriv = ExtendedPrivKey::new_master(cli.network, &seed)?;
    let node_xpriv = xpriv.ckd_priv(&secp, ChildNumber::from_hardened_idx(0)?)?;
    let mint_xpriv = xpriv.ckd_priv(&secp, ChildNumber::from_hardened_idx(1)?)?;

    // Start lightning node
    tracing::info!("Starting lightning node");
    let node = Node::start(
        data_dir.join("node"),
        cli.network,
        rpc_client,
        *node_xpriv.private_key.as_ref(),
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            cli.lightning_port,
        ))),
    )
    .await?;

    // Start mint
    tracing::info!("Starting mint");
    let mint_store = MintRedbDatabase::new(
        data_dir
            .join("mint")
            .to_str()
            .ok_or("mint directory error")?,
    )?;
    let mint = Mint::new(
        mint_xpriv.private_key.as_ref(),
        MintInfo::default(),
        Arc::new(mint_store),
        Amount::ZERO,
        0.0,
    )
    .await?;

    tracing::info!("Starting HTTP server");
    start_server(
        cli.mint_url.as_str(),
        &cli.http_host.to_string(),
        cli.http_port,
        mint,
        Arc::new(node),
    )
    .await?;

    Ok(())
}
