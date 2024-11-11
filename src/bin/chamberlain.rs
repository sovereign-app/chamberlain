use std::{net::SocketAddr, path::PathBuf};

use bitcoin::Network;
use cdk::util::hex;
use chamberlain::rpc::{
    chamberlain_client::ChamberlainClient, AnnounceNodeRequest, CloseChannelRequest,
    ConnectPeerRequest, FundChannelRequest, GetInfoRequest, IssueChannelTokenRequest,
    OpenChannelRequest, ReopenChannelRequest, SweepSpendableBalanceRequest,
};
use clap::{Parser, Subcommand};
use tonic::Request;
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
    /// Issues funds from a channel as a token
    IssueChannelToken {
        /// Channel ID
        #[arg(long)]
        channel_id: String,
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
        token: Option<String>,
        /// Force (only for emergencies). Will result in unbacked e-cash.
        #[arg(long)]
        force: bool,
    },
    /// Re-open a channel from spendable balance
    ReopenChannel {
        /// Node ID
        #[arg(long)]
        node_id: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut client = ChamberlainClient::connect(cli.addr.to_string()).await?;

    match cli.command {
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
            if info.claimable_balance > 0 {
                println!("claimable:        {} sat", info.claimable_balance);
            }
            if let Some(next_claimable_height) = info.next_claimable_height {
                println!("next claimable:   Block {}", next_claimable_height);
            }
            println!("total issued:     {} sat", info.total_issued);
            println!("total redeemed:   {} sat", info.total_redeemed);
            println!("inbound:          {} sat", info.inbound_liquidity);
            println!("network nodes:    {}", info.network_nodes);
            println!("network channels: {}", info.network_channels);
            println!("channels:");
            for (id, balance) in info.channel_balances {
                if info.issuable_channels.contains(&id) {
                    println!("- {}: {} sat*", id, balance);
                } else {
                    println!("- {}: {} sat", id, balance);
                }
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
        Commands::IssueChannelToken { channel_id } => {
            let response = client
                .issue_channel_token(Request::new(IssueChannelTokenRequest { channel_id }))
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
        Commands::SweepSpendableBalance {
            address,
            token,
            force,
        } => {
            let res = client
                .sweep_spendable_balance(Request::new(SweepSpendableBalanceRequest {
                    address,
                    token,
                    force,
                }))
                .await?
                .into_inner();
            println!("txid: {}", res.txid);
        }
        Commands::ReopenChannel { node_id } => {
            let response = client
                .reopen_channel(Request::new(ReopenChannelRequest { node_id }))
                .await?;
            let channel = response.into_inner();
            println!("channel id: {}", channel.channel_id);
            println!("txid:       {}", channel.txid);
            println!("amount:     {}", channel.amount);
        }
    }

    Ok(())
}
