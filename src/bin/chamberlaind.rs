use std::{
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
};

use bitcoin::{
    bip32::{ChildNumber, ExtendedPrivKey},
    consensus::Decodable,
    key::Secp256k1,
    Address, Network, Transaction,
};
use cdk::{
    amount::SplitTarget,
    cdk_lightning::Amount,
    dhke::construct_proofs,
    mint::Mint,
    nuts::{CurrencyUnit, MintBolt11Request, MintInfo, PreMintSecrets, Token},
    secp256k1::rand::random,
    util::{hex, unix_time},
};
use cdk_axum::start_server;
use cdk_ldk::{lightning::ln::ChannelId, BitcoinClient, Node};
use cdk_redb::MintRedbDatabase;
use chamberlain::rpc::{
    chamberlain_server::{Chamberlain, ChamberlainServer},
    ClaimChannelRequest, ClaimChannelResponse, ConnectPeerRequest, ConnectPeerResponse,
    FundChannelRequest, FundChannelResponse, GetInfoRequest, GetInfoResponse, OpenChannelRequest,
    OpenChannelResponse,
};
use clap::Parser;
use redb::TableDefinition;
use tokio::{signal::unix::SignalKind, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tonic::{transport::Server, Request, Response, Status};
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

    // Initialize database
    let db = Database::open(data_dir.join("db"))?;

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
        cdk::Amount::ZERO,
        0.0,
    )
    .await?;

    let cancel_token = CancellationToken::new();

    tracing::info!("Starting RPC server");
    let rpc_addr = SocketAddr::new(cli.rpc_host, cli.rpc_port);
    let rpc_server = RpcServer {
        db,
        mint: mint.clone(),
        mint_url: cli.mint_url.clone(),
        network: cli.network,
        node: node.clone(),
    };
    let rpc_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        let server = Server::builder().add_service(ChamberlainServer::new(rpc_server));
        tokio::select! {
            _ = server.serve(rpc_addr) => {}
            _ = rpc_cancel_token.cancelled() => {}
        }
    });

    tracing::info!("Starting HTTP server");
    let http_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        let http_addr = SocketAddr::new(cli.http_host, cli.http_port);
        tokio::select! {
            _ = start_server(cli.mint_url.as_str(), http_addr, mint, Arc::new(node)) => {}
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

    Ok(())
}

struct RpcServer {
    db: Database,
    mint: Mint,
    mint_url: Url,
    network: Network,
    node: Node,
}

#[tonic::async_trait]
impl Chamberlain for RpcServer {
    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        let mint_info = self.mint.mint_info().map_err(map_mint_error)?;
        let node_info = self.node.get_info().await.map_err(map_ldk_error)?;
        Ok(Response::new(GetInfoResponse {
            name: mint_info.name.unwrap_or_default(),
            description: mint_info.description.unwrap_or_default(),
            node_id: node_info.node_id.to_string(),
            balance: node_info.balance.to_sat(),
            num_channels: node_info.num_channels as u32,
            num_peers: node_info.num_peers as u32,
        }))
    }

    async fn connect_peer(
        &self,
        request: Request<ConnectPeerRequest>,
    ) -> Result<Response<ConnectPeerResponse>, Status> {
        let request = request.into_inner();
        self.node
            .connect_peer(
                request
                    .node_id
                    .parse()
                    .map_err(|_| Status::invalid_argument("invalid node id"))?,
                request
                    .addr
                    .parse()
                    .map_err(|_| Status::invalid_argument("invalid socket address"))?,
            )
            .await
            .map_err(map_ldk_error)?;
        Ok(Response::new(ConnectPeerResponse {}))
    }

    async fn open_channel(
        &self,
        request: Request<OpenChannelRequest>,
    ) -> Result<Response<OpenChannelResponse>, Status> {
        let request = request.into_inner();
        let amount = Amount::from_sat(request.amount);
        tracing::info!(
            "Opening channel with {} ({} sat)",
            request.node_id,
            amount.to_sat()
        );
        let channel = self
            .node
            .open_channel(
                request
                    .node_id
                    .parse()
                    .map_err(|_| Status::invalid_argument("invalid node id"))?,
                amount,
            )
            .await
            .map_err(map_ldk_error)?;
        let address = Address::from_script(&channel.funding_script, self.network)
            .map_err(|_| Status::internal("invalid script"))?;

        let mint_quote = self
            .mint
            .new_mint_quote(
                self.mint_url.clone().into(),
                address.to_string(),
                CurrencyUnit::Sat,
                cdk::Amount::from(amount.to_sat()),
                unix_time() + 3600,
            )
            .await
            .map_err(|_| Status::internal("mint quote failed"))?;
        self.db
            .insert_channel_quote(channel.channel_id.to_string(), mint_quote.id.to_string())
            .await
            .map_err(|_| Status::internal("db error"))?;
        tracing::info!("Created mint quote for channel open: {}", mint_quote.id);

        Ok(Response::new(OpenChannelResponse {
            channel_id: channel.channel_id.to_string(),
            address: Address::from_script(&channel.funding_script, self.network)
                .map_err(|_| Status::internal("invalid script"))?
                .to_string(),
        }))
    }

    async fn fund_channel(
        &self,
        request: Request<FundChannelRequest>,
    ) -> Result<Response<FundChannelResponse>, Status> {
        let request = request.into_inner();
        tracing::info!("Funding channel {}", request.channel_id);
        let channel_id = ChannelId(
            hex::decode(request.channel_id)
                .map_err(|_| Status::invalid_argument("invalid channel id"))?
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid channel id"))?,
        );
        let tx = Transaction::consensus_decode(&mut &request.tx[..])
            .map_err(|_| Status::invalid_argument("invalid transaction"))?;
        let channel = self
            .node
            .fund_channel(channel_id, tx)
            .await
            .map_err(map_ldk_error)?;
        Ok(Response::new(FundChannelResponse {
            channel_id: channel.to_string(),
        }))
    }

    async fn claim_channel(
        &self,
        request: Request<ClaimChannelRequest>,
    ) -> Result<Response<ClaimChannelResponse>, Status> {
        let request = request.into_inner();
        tracing::info!("Claiming channel {}", request.channel_id);
        let channel_id = ChannelId(
            hex::decode(&request.channel_id)
                .map_err(|_| Status::internal("invalid channel id"))?
                .try_into()
                .map_err(|_| Status::internal("invalid channel id"))?,
        );
        let quote_id = self
            .db
            .get_channel_quote(request.channel_id)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or(Status::not_found("quote not found"))?;

        if !self.node.is_channel_ready(channel_id) {
            return Err(Status::failed_precondition("channel not ready"));
        }

        let keyset_id = self
            .mint
            .keysets()
            .await
            .map_err(|_| Status::internal("loading keysets error"))?
            .keysets
            .into_iter()
            .filter_map(|k| {
                if k.active && k.unit == CurrencyUnit::Sat {
                    Some(k.id)
                } else {
                    None
                }
            })
            .next()
            .ok_or(Status::internal("no active keyset found"))?;
        let keys = self
            .mint
            .keyset_pubkeys(&keyset_id)
            .await
            .map_err(|_| Status::internal("loading keyset public keys error"))?
            .keysets
            .into_iter()
            .next()
            .ok_or(Status::internal("no keyset found"))?
            .keys;

        let mut quote = self
            .mint
            .mint_quotes()
            .await
            .map_err(|_| Status::internal("mint quotes error"))?
            .into_iter()
            .find(|q| q.id == quote_id)
            .ok_or(Status::not_found("quote not found"))?;
        quote.paid = true;
        self.mint
            .update_mint_quote(quote.clone())
            .await
            .map_err(|_| Status::internal("mint quote update failed"))?;

        let secrets = PreMintSecrets::random(keyset_id, quote.amount, &SplitTarget::None)
            .map_err(|_| Status::internal("secrets generation error"))?;
        let res = self
            .mint
            .process_mint_request(MintBolt11Request {
                quote: quote.id,
                outputs: secrets.blinded_messages(),
            })
            .await
            .map_err(|_| Status::internal("mint processing error"))?;
        let proofs = construct_proofs(res.signatures, secrets.rs(), secrets.secrets(), &keys)
            .map_err(|_| Status::internal("construct proofs error"))?;
        let token = Token::new(
            self.mint_url.clone().into(),
            proofs,
            None,
            Some(CurrencyUnit::Sat),
        )
        .map_err(|_| Status::internal("token creation error"))?;

        Ok(Response::new(ClaimChannelResponse {
            token: token.to_string(),
        }))
    }
}

fn map_mint_error(e: cdk::mint::error::Error) -> Status {
    Status::internal(e.to_string())
}

fn map_ldk_error(e: cdk_ldk::Error) -> Status {
    Status::internal(e.to_string())
}

const CHANNEL_QUOTES_TABLE: TableDefinition<String, String> =
    TableDefinition::new("channel_quotes");

struct Database {
    db: Arc<RwLock<redb::Database>>,
}

impl Database {
    fn open(path: PathBuf) -> Result<Self, redb::Error> {
        let db = redb::Database::create(path)?;
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
        })
    }

    async fn insert_channel_quote(
        &self,
        channel_id: String,
        quote_id: String,
    ) -> Result<(), redb::Error> {
        let db = self.db.read().await;
        let write_tx = db.begin_write()?;
        {
            let mut table = write_tx.open_table(CHANNEL_QUOTES_TABLE)?;
            let _ = table.insert(channel_id, quote_id)?;
        }
        write_tx.commit()?;
        Ok(())
    }

    async fn get_channel_quote(&self, channel_id: String) -> Result<Option<String>, redb::Error> {
        let db = self.db.read().await;
        let read_tx = db.begin_read()?;
        let table = read_tx.open_table(CHANNEL_QUOTES_TABLE)?;
        let quote_id = table.get(channel_id)?;
        Ok(quote_id.map(|v| v.value()))
    }
}
