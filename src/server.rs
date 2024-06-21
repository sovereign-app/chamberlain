use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use bitcoin::{consensus::Decodable, Address, Network, Transaction};
use cdk::{
    amount::SplitTarget,
    cdk_lightning::Amount,
    dhke::construct_proofs,
    mint::Mint,
    nuts::{CurrencyUnit, MintBolt11Request, PreMintSecrets, Token},
    util::{hex, unix_time},
};
use cdk_ldk::{lightning::ln::ChannelId, Node};
use tonic::{Request, Response, Status};
use tracing_subscriber::EnvFilter;
use url::Url;

use crate::rpc::{
    chamberlain_server::Chamberlain, ClaimChannelRequest, ClaimChannelResponse, ConnectPeerRequest,
    ConnectPeerResponse, FundChannelRequest, FundChannelResponse, GetInfoRequest, GetInfoResponse,
    OpenChannelRequest, OpenChannelResponse,
};

pub const KEY_FILE: &str = "key";
pub const MINT_DB_FILE: &str = "mint";
pub const NODE_DIR: &str = "node";

pub struct RpcServer {
    config: Config,
    mint: Mint,
    node: Node,
}

impl RpcServer {
    pub fn new(config: Config, mint: Mint, node: Node) -> Self {
        Self { config, mint, node }
    }
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
        let address = Address::from_script(&channel.funding_script, self.config.network)
            .map_err(|_| Status::internal("invalid script"))?;

        let mint_quote = self
            .mint
            .new_mint_quote(
                self.config.mint_url.clone().into(),
                address.to_string(),
                CurrencyUnit::Sat,
                cdk::Amount::from(amount.to_sat()),
                unix_time() + 3600,
            )
            .await
            .map_err(|_| Status::internal("mint quote failed"))?;
        tracing::info!("Created mint quote for channel open: {}", mint_quote.id);

        Ok(Response::new(OpenChannelResponse {
            channel_id: channel.channel_id.to_string(),
            address: address.to_string(),
            quote_id: mint_quote.id,
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
            .find(|q| q.id == request.quote_id)
            .ok_or(Status::not_found("quote not found"))?;
        if Into::<u64>::into(quote.amount)
            != self
                .node
                .get_open_channel_value(channel_id)
                .await
                .map_err(|_| Status::internal("channel db error"))?
                .to_sat()
        {
            return Err(Status::failed_precondition("quote amount incorrect"));
        }
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
            self.config.mint_url.clone().into(),
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

macro_rules! create_config_structs {
    ($(($field:ident: $type:ty, $doc:expr),)*) => {
        #[derive(Clone, Debug, serde::Deserialize)]
        pub struct Config {
            $(
                #[doc = $doc]
                pub $field: $type,
            )*
        }

        impl Config {
            pub fn new(cli: Cli) -> Self {
                let default = Self::default();
                Self {
                    $(
                        $field: cli.$field.unwrap_or(default.$field),
                    )*
                }
            }
        }

        #[derive(Debug, Default, serde::Deserialize, clap::Parser)]
        #[clap(name = "chamberlaind", version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"), about = "Chamberlain daemon")]
        pub struct Cli {
            $(
                #[doc = $doc]
                #[arg(long)]
                $field: Option<$type>,
            )*
        }

        impl Cli {
            pub fn override_values(self, cli: Cli) -> Self {
                Self {
                    $(
                        $field: cli.$field.or(self.$field),
                    )*
                }
            }
        }
    };
}

create_config_structs!(
    (data_dir: PathBuf, "Data directory"),
    (network: Network, "Network"),
    (bitcoind_rpc_url: Url, "Bitcoind RPC URL"),
    (bitcoind_rpc_user: String, "Bitcoind RPC user"),
    (bitcoind_rpc_password: String, "Bitcoind RPC password"),
    (lightning_port: u16, "Lightning network p2p port"),
    (rpc_host: IpAddr, "Host IP to bind the RPC server"),
    (rpc_port: u16, "Port to bind the RPC server"),
    (http_host: IpAddr, "Host IP to bind the HTTP server"),
    (http_port: u16, "Port to bind the HTTP server"),
    (mint_url: Url, "Mint URL"),
    (mint_name: String, "Mint name"),
    (mint_description: String, "Mint description"),
    (log_level: LogLevel, "Log level"),
    (unmanaged: bool, "Unmanaged mode"),
);

#[derive(Debug, Clone, Copy, serde::Deserialize, clap::ValueEnum)]
pub enum LogLevel {
    Trace,
    TraceAll,
    Debug,
    DebugAll,
    Info,
    Warn,
    Error,
    Off,
}

impl Into<EnvFilter> for LogLevel {
    fn into(self) -> EnvFilter {
        match self {
            LogLevel::Trace => EnvFilter::new("debug,cdk=trace,chamberlain=trace"),
            LogLevel::TraceAll => EnvFilter::new("trace"),
            LogLevel::Debug => EnvFilter::new("info,cdk=debug,chamberlain=debug"),
            LogLevel::DebugAll => EnvFilter::new("debug"),
            LogLevel::Info => EnvFilter::new("info"),
            LogLevel::Warn => EnvFilter::new("warn"),
            LogLevel::Error => EnvFilter::new("error"),
            LogLevel::Off => EnvFilter::new("off"),
        }
    }
}

impl Config {
    pub fn load(cli: Cli) -> Self {
        let default = Self::default();
        let config_file = cli
            .data_dir
            .as_ref()
            .map_or(default.data_dir.join("config.toml"), |d| {
                d.join("config.toml")
            });

        let file_cli: Option<Cli> = match fs::read_to_string(&config_file) {
            Ok(s) => toml::from_str(&s).ok(),
            Err(e) => {
                tracing::warn!(
                    "Failed to read config file ({}): {}",
                    config_file.display(),
                    e
                );
                None
            }
        };
        let overrides = file_cli.unwrap_or_default().override_values(cli);
        Config::new(overrides)
    }

    pub fn data_dir(&self) -> PathBuf {
        if let Some(home_dir) = dirs::home_dir() {
            if let Ok(without_tilde) = self.data_dir.strip_prefix("~") {
                home_dir.join(without_tilde)
            } else {
                self.data_dir.clone()
            }
        } else {
            self.data_dir.clone()
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("~/.chamberlain"),
            network: Network::Bitcoin,
            bitcoind_rpc_url: "http://127.0.0.1:8332".parse().unwrap(),
            bitcoind_rpc_user: "user".to_string(),
            bitcoind_rpc_password: "password".to_string(),
            lightning_port: 9735,
            rpc_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            rpc_port: 3339,
            http_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port: 3338,
            mint_url: "http://localhost:3338".parse().unwrap(),
            mint_name: "Chamberlain".to_string(),
            mint_description: "Chamberlain mint".to_string(),
            log_level: LogLevel::Info,
            unmanaged: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_load() {
        let config = Config::load(Cli::default());
        assert_eq!(config.data_dir, PathBuf::from("~/.chamberlain"));
        assert_eq!(config.network, Network::Bitcoin);
    }

    #[test]
    fn test_override_config_load() {
        let cli = Cli {
            data_dir: Some(PathBuf::from("/tmp")),
            network: Some(Network::Regtest),
            ..Default::default()
        };
        let config = Config::load(cli);
        assert_eq!(config.data_dir, PathBuf::from("/tmp"));
        assert_eq!(config.network, Network::Regtest);
    }

    #[test]
    fn test_override_cli_values() {
        let file = Cli {
            data_dir: Some(PathBuf::from("/tmp")),
            network: Some(Network::Bitcoin),
            ..Default::default()
        };
        let cli = Cli {
            data_dir: Some(PathBuf::from("/tmp")),
            network: Some(Network::Regtest),
            ..Default::default()
        };
        let cli = file.override_values(cli);
        assert_eq!(cli.data_dir, Some(PathBuf::from("/tmp")));
        assert_eq!(cli.network, Some(Network::Regtest));
    }
}
