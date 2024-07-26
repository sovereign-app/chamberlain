use std::{fs, io, net::SocketAddr, path::PathBuf};

use base64::{engine::general_purpose, Engine};
use bitcoin::Network;
use cdk::util::hex;
use chamberlain::rpc::{
    chamberlain_client::ChamberlainClient, client_auth_interceptor, finish_auth_token_base64,
    start_auth_token, AnnounceNodeRequest, ClaimChannelRequest, CloseChannelRequest,
    ConnectPeerRequest, FundChannelRequest, GenerateAuthTokenRequest, GetInfoRequest,
    OpenChannelRequest, SweepSpendableBalanceRequest,
};
use clap::{Parser, Subcommand};
use fast_socks5::{
    client::{Config, Socks5Stream},
    SocksError,
};
use hyper_util::rt::TokioIo;
use tokio::net::lookup_host;
use tonic::{
    transport::{Certificate, ClientTlsConfig, Endpoint, Uri},
    Request,
};
use tower::service_fn;
use url::Url;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Address of RPC server
    #[arg(short, long, default_value = "http://127.0.0.1:3339")]
    addr: Url,

    /// Bitcoin Network
    #[arg(short, long, default_value = "bitcoin")]
    network: Network,

    /// Certificate authority file
    #[arg(short, long)]
    ca_file: Option<PathBuf>,

    /// Socks5 proxy
    #[arg(short, long)]
    proxy: Option<Url>,

    /// Auth token
    #[arg(short, long)]
    token: Option<String>,

    /// Auth token file
    #[arg(short = 'f', long, default_value = "~/.chamberlain/auth_token")]
    token_file: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new auth token
    GenerateAuthToken {
        /// Password
        password: Option<String>,
    },
    /// Get info
    GetInfo,
    /// Announce node
    AnnounceNode {
        /// IP Address
        #[arg(long)]
        addr: SocketAddr,
    },
    /// Connect to a peer
    ConnectPeer {
        /// Node ID
        #[arg(long)]
        node_id: String,
        /// Socket address
        #[arg(long)]
        addr: SocketAddr,
    },
    /// Open a channel
    OpenChannel {
        /// Node ID
        #[arg(long)]
        node_id: String,
        /// Amount in satoshis
        #[arg(long)]
        amount: u64,
    },
    /// Fund a channel
    FundChannel {
        /// Channel ID
        #[arg(long)]
        channel_id: String,
        /// Hex-encoded transaction
        #[arg(long)]
        tx: String,
    },
    /// Claim funds from a channel
    ClaimChannel {
        /// Channel ID
        #[arg(long)]
        channel_id: String,
        /// Quote ID
        #[arg(long)]
        quote_id: String,
    },
    /// Close channel
    CloseChannel {
        /// Channel ID
        #[arg(long)]
        channel_id: String,
        /// Token
        #[arg(long)]
        token: String,
        /// Address
        #[arg(long)]
        address: String,
    },
    /// Sweep spendable funds
    SweepSpendableBalance {
        /// Address
        #[arg(long)]
        address: String,
        /// Token
        #[arg(long)]
        token: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let token = if let Some(token) = cli.token.map(|t| general_purpose::STANDARD.decode(t)) {
        token?
    } else {
        let token_file = if let Some(home_dir) = dirs::home_dir() {
            if let Ok(without_tilde) = cli.token_file.strip_prefix("~") {
                home_dir.join(without_tilde)
            } else {
                cli.token_file
            }
        } else {
            cli.token_file
        };
        fs::read(token_file)?
    };

    // TODO DRY
    let proxy_addr =
        if let Some(proxy) = cli.proxy {
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

    let mut endpoint = Endpoint::from_shared(cli.addr.to_string())?;
    if cli.addr.scheme() == "https" {
        let mut tls_config = ClientTlsConfig::new();
        if let Some(ca_file) = cli.ca_file {
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
    let mut client = ChamberlainClient::with_interceptor(channel, client_auth_interceptor(&token)?);

    match cli.command {
        Commands::GenerateAuthToken { password } => {
            let password = password.unwrap_or_else(|| {
                rpassword::prompt_password("Password: ").expect("Failed to read password")
            });
            let (s, m) = start_auth_token(&password);
            let res = client
                .generate_auth_token(Request::new(GenerateAuthTokenRequest { message: m }))
                .await?
                .into_inner();
            let token = finish_auth_token_base64(s, res.message)?;
            println!("{}", token);
        }
        Commands::GetInfo => {
            let response = client.get_info(Request::new(GetInfoRequest {})).await?;
            let info = response.into_inner();
            println!("name:             {}", info.name);
            println!("description:      {}", info.description);
            println!("node id:          {}", info.node_id);
            println!(
                "public ip:        {}",
                info.public_ip.unwrap_or("unknown".to_string())
            );
            println!(
                "balance:          {} sat",
                info.channel_balances.values().sum::<u64>()
            );
            if info.spendable_balance > 0 {
                println!("spendable:        {} sat", info.spendable_balance);
            }
            println!("inbound:          {} sat", info.inbound_liquidity);
            println!("network nodes:    {}", info.network_nodes);
            println!("network channels: {}", info.network_channels);
            println!("channels:");
            for (id, balance) in info.channel_balances {
                println!("- {}: {} sat", id, balance);
            }
            println!("peers:");
            for (id, addr) in info.peers {
                println!("- {}: {}", id, addr);
            }
        }
        Commands::AnnounceNode { addr } => {
            client
                .announce_node(Request::new(AnnounceNodeRequest {
                    ip_address: addr.to_string(),
                }))
                .await?;
        }
        Commands::ConnectPeer { node_id, addr } => {
            client
                .connect_peer(Request::new(ConnectPeerRequest {
                    node_id,
                    addr: addr.to_string(),
                }))
                .await?;
        }
        Commands::OpenChannel { node_id, amount } => {
            let response = client
                .open_channel(Request::new(OpenChannelRequest { node_id, amount }))
                .await?;
            let channel = response.into_inner();
            println!("channel id: {}", channel.channel_id);
            println!("address:    {}", channel.address);
            println!("quote id:   {}", channel.quote_id);
        }
        Commands::FundChannel { channel_id, tx } => {
            let response = client
                .fund_channel(Request::new(FundChannelRequest {
                    channel_id,
                    tx: hex::decode(&tx)?,
                }))
                .await?
                .into_inner();
            println!("channel id: {}", response.channel_id);
        }
        Commands::ClaimChannel {
            channel_id,
            quote_id,
        } => {
            let response = client
                .claim_channel(Request::new(ClaimChannelRequest {
                    channel_id,
                    quote_id,
                }))
                .await?
                .into_inner();
            println!("{}", response.token);
        }
        Commands::CloseChannel {
            channel_id,
            token,
            address,
        } => {
            client
                .close_channel(Request::new(CloseChannelRequest {
                    channel_id,
                    token,
                    address,
                }))
                .await?;
        }
        Commands::SweepSpendableBalance { address, token } => {
            let res = client
                .sweep_spendable_balance(Request::new(SweepSpendableBalanceRequest {
                    address,
                    token,
                }))
                .await?
                .into_inner();
            println!("txid: {}", res.txid);
        }
    }

    Ok(())
}
