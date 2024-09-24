use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use bitcoin::{
    consensus::Decodable,
    secp256k1::rand::{self, distributions::Alphanumeric, Rng},
    Address, Network, Transaction,
};
use cdk::{
    amount::{Amount, SplitTarget},
    dhke::construct_proofs,
    mint::Mint,
    mint_url::MintUrl,
    nuts::{
        ContactInfo, CurrencyUnit, MeltBolt11Request, MeltQuoteState, MintBolt11Request,
        MintQuoteState, PreMintSecrets, Token,
    },
    util::{hex, unix_time},
};
use cdk_ldk::{lightning::ln::types::ChannelId, Node};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use tracing_subscriber::EnvFilter;
use url::Url;

use crate::rpc::{
    chamberlain_server::Chamberlain, finish_auth_token, start_auth_token, AnnounceNodeRequest,
    AnnounceNodeResponse, ClaimChannelRequest, ClaimChannelResponse, CloseChannelRequest,
    CloseChannelResponse, ConnectPeerRequest, ConnectPeerResponse, FundChannelRequest,
    FundChannelResponse, GenerateAuthTokenRequest, GenerateAuthTokenResponse, GetInfoRequest,
    GetInfoResponse, OpenChannelRequest, OpenChannelResponse, ReopenChannelRequest,
    ReopenChannelResponse, SweepSpendableBalanceRequest, SweepSpendableBalanceResponse,
};

pub const AUTH_TOKEN_FILE: &str = "auth_token";
pub const CONFIG_FILE: &str = "config.toml";
pub const KEY_FILE: &str = "key";
pub const MINT_DB_FILE: &str = "mint";
pub const NODE_DIR: &str = "node";

#[derive(Clone)]
pub struct RpcServer {
    config: Config,
    mint: Mint,
    node: Node,
    restart_token: CancellationToken,
}

impl RpcServer {
    pub fn new(config: Config, mint: Mint, node: Node, restart_token: CancellationToken) -> Self {
        Self {
            config,
            mint,
            node,
            restart_token,
        }
    }
}

#[tonic::async_trait]
impl Chamberlain for RpcServer {
    async fn generate_auth_token(
        &self,
        request: Request<GenerateAuthTokenRequest>,
    ) -> Result<Response<GenerateAuthTokenResponse>, Status> {
        let request = request.into_inner();
        let (s, m) = start_auth_token(&self.config.password);
        let token =
            finish_auth_token(s, request.message).map_err(|e| Status::internal(e.to_string()))?;
        fs::write(self.config.data_dir().join(AUTH_TOKEN_FILE), token)
            .map_err(|e| Status::internal(e.to_string()))?;
        self.restart_token.cancel();
        Ok(Response::new(GenerateAuthTokenResponse { message: m }))
    }

    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        let mint_info = self.mint.mint_info();
        let node_info = self.node.get_info().await.map_err(map_ldk_error)?;
        let total_issued = Amount::try_sum(
            self.mint
                .total_issued()
                .await
                .map_err(|_| Status::internal("mint error"))?
                .into_iter()
                .map(|(_, v)| v),
        )
        .map_err(|_| Status::internal("amount error"))?;
        let total_redeemed = Amount::try_sum(
            self.mint
                .total_redeemed()
                .await
                .map_err(|_| Status::internal("mint error"))?
                .into_iter()
                .map(|(_, v)| v),
        )
        .map_err(|_| Status::internal("amount error"))?;

        Ok(Response::new(GetInfoResponse {
            name: mint_info.name.clone().unwrap_or_default(),
            description: mint_info.description.clone().unwrap_or_default(),
            node_id: node_info.node_id.to_string(),
            channel_balances: node_info
                .channel_balances
                .into_iter()
                .map(|(channel_id, balance)| (channel_id.to_string(), balance.into()))
                .collect(),
            peers: node_info
                .peers
                .into_iter()
                .map(|(node_id, addr)| (node_id.to_string(), addr.to_string()))
                .collect(),
            spendable_balance: node_info.spendable_balance.into(),
            inbound_liquidity: node_info.inbound_liquidity.into(),
            network_nodes: node_info.network_nodes as u32,
            network_channels: node_info.network_channels as u32,
            public_ip: public_ip::addr().await.map(|ip| ip.to_string()),
            claimable_balance: node_info.claimable_balance.into(),
            next_claimable_height: node_info.next_claimable_height,
            total_issued: total_issued.into(),
            total_redeemed: total_redeemed.into(),
        }))
    }

    async fn announce_node(
        &self,
        request: Request<AnnounceNodeRequest>,
    ) -> Result<Response<AnnounceNodeResponse>, Status> {
        let request = request.into_inner();
        let addrs = vec![request
            .ip_address
            .parse()
            .map_err(|_| Status::invalid_argument("invalid ip address"))?];
        tracing::info!("Announcing node with address: {}", addrs[0]);
        self.node
            .announce_node(&self.config.mint_name, self.config.mint_color(), addrs)
            .map_err(map_ldk_error)?;
        Ok(Response::new(AnnounceNodeResponse {}))
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
        let amount = Amount::from(request.amount);
        tracing::info!("Opening channel with {} ({} sat)", request.node_id, amount);
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
            .map_err(|e| map_internal_error(e, "address error"))?;

        let mint_quote = self
            .mint
            .new_mint_quote(
                self.config.mint_url.clone().into(),
                address.to_string(),
                CurrencyUnit::Sat,
                amount,
                unix_time() + 3600,
                address.to_string(),
            )
            .await
            .map_err(|e| map_internal_error(e, "mint quote failed"))?;
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
        let channel_id = parse_channel_id(&request.channel_id)?;
        tracing::info!("Funding channel {}", request.channel_id);
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
        let channel_id = parse_channel_id(&request.channel_id)?;
        tracing::info!("Claiming channel {}", request.channel_id);

        if !self.node.is_channel_ready(channel_id) {
            return Err(Status::failed_precondition("channel not ready"));
        }

        let keyset_id = self
            .mint
            .keysets()
            .await
            .map_err(|e| map_internal_error(e, "loading keysets error"))?
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
            .map_err(|e| map_internal_error(e, "loading keyset public keys error"))?
            .keysets
            .into_iter()
            .next()
            .ok_or(Status::internal("no keyset found"))?
            .keys;

        let mut quote = self
            .mint
            .mint_quotes()
            .await
            .map_err(|e| map_internal_error(e, "mint quotes error"))?
            .into_iter()
            .find(|q| q.id == request.quote_id)
            .ok_or(Status::not_found("quote not found"))?;
        if quote.amount
            != self
                .node
                .get_open_channel_value(channel_id)
                .await
                .map_err(|e| map_internal_error(e, "channel db error"))?
        {
            return Err(Status::failed_precondition("quote amount incorrect"));
        }
        quote.state = MintQuoteState::Paid;
        self.mint
            .update_mint_quote(quote.clone())
            .await
            .map_err(|e| map_internal_error(e, "mint quote update failed"))?;

        let secrets = PreMintSecrets::random(keyset_id, quote.amount, &SplitTarget::None)
            .map_err(|e| map_internal_error(e, "secrets generation error"))?;
        let res = self
            .mint
            .process_mint_request(MintBolt11Request {
                quote: quote.id,
                outputs: secrets.blinded_messages(),
            })
            .await
            .map_err(|e| map_internal_error(e, "mint processing error"))?;
        let proofs = construct_proofs(res.signatures, secrets.rs(), secrets.secrets(), &keys)
            .map_err(|e| map_internal_error(e, "construct proofs error"))?;
        let token = Token::new(
            self.config.mint_url.clone().into(),
            proofs,
            None,
            Some(CurrencyUnit::Sat),
        );

        Ok(Response::new(ClaimChannelResponse {
            token: token.to_string(),
        }))
    }

    async fn close_channel(
        &self,
        request: Request<CloseChannelRequest>,
    ) -> Result<Response<CloseChannelResponse>, Status> {
        let request = request.into_inner();
        let channel_id = parse_channel_id(&request.channel_id)?;
        tracing::info!("Closing channel {}", request.channel_id);

        let address = Address::from_str(&request.address)
            .map_err(|_| Status::invalid_argument("invalid address"))?
            .require_network(self.config.network)
            .map_err(|_| Status::invalid_argument("invalid address network"))?;
        let token = Token::from_str(&request.token)
            .map_err(|_| Status::invalid_argument("invalid token"))?;
        let channel_balance = self
            .node
            .get_channel_info(channel_id)
            .map_err(|e| map_internal_error(e, "channel not available"))?
            .balance;
        if token
            .value()
            .map_err(|_| Status::invalid_argument("invalid token amount"))?
            != channel_balance
        {
            return Err(Status::invalid_argument("incorrect token amount"));
        }

        let mut melt_quote = self
            .mint
            .new_melt_quote(
                address.to_string(),
                CurrencyUnit::Sat,
                channel_balance.into(),
                Amount::ZERO,
                unix_time() + 60,
                address.to_string(),
            )
            .await
            .map_err(|e| map_internal_error(e, "melt quote error"))?;

        self.node
            .close_channel(channel_id, address.script_pubkey())
            .await
            .map_err(|e| map_internal_error(e, "close channel error"))?;

        melt_quote.state = MeltQuoteState::Paid;
        self.mint
            .update_melt_quote(melt_quote.clone())
            .await
            .map_err(|e| map_internal_error(e, "melt quote update error"))?;
        self.mint
            .process_melt_request(
                &MeltBolt11Request {
                    quote: melt_quote.id,
                    inputs: token
                        .proofs()
                        .into_iter()
                        .map(|(_, proofs)| proofs)
                        .flatten()
                        .collect(),
                    outputs: None,
                },
                None,
                channel_balance.into(),
            )
            .await
            .map_err(|e| map_internal_error(e, "melt quote process error"))?;

        Ok(Response::new(CloseChannelResponse {}))
    }

    async fn sweep_spendable_balance(
        &self,
        request: Request<SweepSpendableBalanceRequest>,
    ) -> Result<Response<SweepSpendableBalanceResponse>, Status> {
        let request = request.into_inner();
        let address = Address::from_str(&request.address)
            .map_err(|_| Status::invalid_argument("invalid address"))?
            .require_network(self.config.network)
            .map_err(|_| Status::invalid_argument("invalid address network"))?;

        if request.token.is_none() && !request.force {
            return Err(Status::invalid_argument("missing token"));
        }

        if request.token.is_some() && request.force {
            return Err(Status::invalid_argument("both token and force set"));
        }

        let spendable_balance = self
            .node
            .get_spendable_output_balance()
            .await
            .map_err(|e| map_internal_error(e, "spendable output balance error"))?;

        if let Some(token) = request.token.as_ref() {
            let token =
                Token::from_str(token).map_err(|_| Status::invalid_argument("invalid token"))?;

            let melt_quote = self
                .mint
                .new_melt_quote(
                    address.to_string(),
                    CurrencyUnit::Sat,
                    spendable_balance.into(),
                    Amount::ZERO,
                    unix_time() + 60,
                    address.to_string(),
                )
                .await
                .map_err(|e| map_internal_error(e, "melt quote error"))?;

            let melt_request = MeltBolt11Request {
                quote: melt_quote.id,
                inputs: token
                    .proofs()
                    .into_iter()
                    .map(|(_, proofs)| proofs)
                    .flatten()
                    .collect(),
                outputs: None,
            };

            let mut melt_quote = self
                .mint
                .verify_melt_request(&melt_request)
                .await
                .map_err(|_| Status::invalid_argument("invalid melt request"))?;
            melt_quote.state = MeltQuoteState::Paid;
            self.mint
                .update_melt_quote(melt_quote)
                .await
                .map_err(|e| map_internal_error(e, "melt quote update error"))?;

            self.mint
                .process_melt_request(&melt_request, None, spendable_balance.into())
                .await
                .map_err(|e| map_internal_error(e, "melt quote process error"))?;
        }

        let txid = self
            .node
            .sweep_spendable_outputs(address.script_pubkey())
            .await
            .map_err(|e| map_internal_error(e, "sweep spendable outputs error"))?;

        Ok(Response::new(SweepSpendableBalanceResponse {
            txid: txid.to_string(),
        }))
    }

    async fn reopen_channel(
        &self,
        request: Request<ReopenChannelRequest>,
    ) -> Result<Response<ReopenChannelResponse>, Status> {
        let request = request.into_inner();
        tracing::info!("Re-opening channel with {}", request.node_id);
        let channel = self
            .node
            .reopen_channel_from_spendable_outputs(
                request
                    .node_id
                    .parse()
                    .map_err(|_| Status::invalid_argument("invalid node id"))?,
            )
            .await
            .map_err(map_ldk_error)?;
        tracing::info!(
            "Re-opened channel for {} sats (channel_id={})",
            channel.amount,
            channel.channel_id
        );
        Ok(Response::new(ReopenChannelResponse {
            channel_id: channel.channel_id.to_string(),
            address: Address::from_script(&channel.funding_script, self.config.network)
                .map_err(|e| map_internal_error(e, "address error"))?
                .to_string(),
            amount: channel.amount.into(),
            txid: channel.txid.to_string(),
        }))
    }
}

fn map_internal_error<E: ToString>(e: E, msg: &str) -> Status {
    tracing::error!("{}: {}", msg, e.to_string());
    Status::internal(msg)
}

fn map_ldk_error(e: cdk_ldk::Error) -> Status {
    Status::internal(e.to_string())
}

fn parse_channel_id(channel_id: &str) -> Result<ChannelId, Status> {
    Ok(ChannelId(
        hex::decode(channel_id)
            .map_err(|_| Status::invalid_argument("invalid channel id"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid channel id"))?,
    ))
}

macro_rules! create_config_structs {
    ($(($field:ident: $type:ty, $doc:expr),)*) => {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    (lightning_port: u16, "Lightning Network p2p port"),
    (lightning_announce_addr: SocketAddr, "Lightning Network announce address"),
    (lightning_auto_announce: bool, "Auto announce lightning node"),
    (rpc_host: IpAddr, "Host IP to bind the RPC server"),
    (rpc_port: u16, "Port to bind the RPC server"),
    (http_host: IpAddr, "Host IP to bind the HTTP server"),
    (http_port: u16, "Port to bind the HTTP server"),
    (mint_url: MintUrl, "Mint URL"),
    (mint_name: String, "Mint name and LN alias"),
    (mint_description: String, "Mint description"),
    (mint_color: String, "Mint LN alias color"),
    (mint_contact_email: String, "Mint contact email"),
    (mint_contact_npub: String, "Mint contact nostr public key"),
    (mint_contact_twitter: String, "Mint contact twitter"),
    (mint_motd: String, "Mint message of the day"),
    (password: String, "RPC auth token password"),
    (log_level: LogLevel, "Log level"),
);

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, clap::ValueEnum)]
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
            .map_or(default.data_dir.join(CONFIG_FILE), |d| d.join(CONFIG_FILE));

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

    pub fn mint_color(&self) -> [u8; 3] {
        let color = self.mint_color.trim_start_matches('#');
        let r = u8::from_str_radix(&color[0..2], 16).unwrap_or(0);
        let g = u8::from_str_radix(&color[2..4], 16).unwrap_or(0);
        let b = u8::from_str_radix(&color[4..6], 16).unwrap_or(0);
        [r, g, b]
    }

    pub fn mint_contact(&self) -> Option<Vec<ContactInfo>> {
        let mut contact = Vec::new();
        if !self.mint_contact_email.is_empty() {
            contact.push(ContactInfo {
                method: "email".to_string(),
                info: self.mint_contact_email.clone(),
            });
        }
        if !self.mint_contact_npub.is_empty() {
            contact.push(ContactInfo {
                method: "nostr".to_string(),
                info: self.mint_contact_npub.clone(),
            });
        }
        if !self.mint_contact_twitter.is_empty() {
            contact.push(ContactInfo {
                method: "twitter".to_string(),
                info: self.mint_contact_twitter.clone(),
            });
        }
        if contact.is_empty() {
            None
        } else {
            Some(contact)
        }
    }

    pub fn mint_motd(&self) -> Option<String> {
        if self.mint_motd.is_empty() {
            None
        } else {
            Some(self.mint_motd.clone())
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_file = self.data_dir().join(CONFIG_FILE);
        Ok(fs::write(config_file, toml::to_string(self)?)?)
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
            lightning_announce_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9735),
            lightning_auto_announce: true,
            rpc_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            rpc_port: 3339,
            http_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port: 3338,
            mint_url: "http://localhost:3338".parse().unwrap(),
            mint_name: "Chamberlain".to_string(),
            mint_description: "A chamberlain powered cashu mint.".to_string(),
            mint_color: "#853DB5".to_string(),
            mint_contact_email: "".to_string(),
            mint_contact_npub: "".to_string(),
            mint_contact_twitter: "".to_string(),
            mint_motd: "".to_string(),
            password: generate_password(),
            log_level: LogLevel::Info,
        }
    }
}

fn generate_password() -> String {
    let mut rng = rand::thread_rng();
    let password: String = std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .filter(|c| !matches!(c, b'I' | b'l' | b'O' | b'0'))
        .take(8)
        .map(char::from)
        .collect();
    password
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
