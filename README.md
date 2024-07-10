# Chamberlain

> Cashu Mint with Integrated Lightning Node

**Alpha Notice**: The software is currently in alpha-testing. Use at your own
risk.

This project aims to substantially increase the number of
[Uncle Jims](https://thebitcoinmanual.com/behind-btc/nodes/uncle-jim-node/)
running mints who can manage day-to-day Bitcoin transactions for friends and
family.

## Running the Mint

Chamberlain ships with two binaries: `chamberlaind`, the long-running daemon,
and `chamberlain`, the management cli tool.

```
chamberlaind --mint-url=http://mint.url:3338
```

All configurable options are available from the help menu:

```
$ chamberlaind --help
Chamberlain daemon

Usage: chamberlaind [OPTIONS]

Options:
      --data-dir <DATA_DIR>
          Data directory
      --network <NETWORK>
          Network
      --bitcoind-rpc-url <BITCOIND_RPC_URL>
          Bitcoind RPC URL
      --bitcoind-rpc-user <BITCOIND_RPC_USER>
          Bitcoind RPC user
      --bitcoind-rpc-password <BITCOIND_RPC_PASSWORD>
          Bitcoind RPC password
      --lightning-port <LIGHTNING_PORT>
          Lightning Network p2p port
      --lightning-announce-addr <LIGHTNING_ANNOUNCE_ADDR>
          Lightning Network announce address
      --lightning-auto-announce <LIGHTNING_AUTO_ANNOUNCE>
          Auto announce lightning node [possible values: true, false]
      --rpc-host <RPC_HOST>
          Host IP to bind the RPC server
      --rpc-port <RPC_PORT>
          Port to bind the RPC server
      --http-host <HTTP_HOST>
          Host IP to bind the HTTP server
      --http-port <HTTP_PORT>
          Port to bind the HTTP server
      --mint-url <MINT_URL>
          Mint URL
      --mint-name <MINT_NAME>
          Mint name and LN alias
      --mint-description <MINT_DESCRIPTION>
          Mint description
      --mint-color <MINT_COLOR>
          Mint LN alias color
      --mint-contact-email <MINT_CONTACT_EMAIL>
          Mint contact email
      --mint-contact-npub <MINT_CONTACT_NPUB>
          Mint contact nostr public key
      --mint-contact-twitter <MINT_CONTACT_TWITTER>
          Mint contact twitter
      --mint-motd <MINT_MOTD>
          Mint message of the day
      --password <PASSWORD>
          RPC auth token password
      --log-level <LOG_LEVEL>
          Log level [possible values: trace, trace-all, debug, debug-all, info, warn, error, off]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Building from Source

It is recommended to use [cargo](https://github.com/rust-lang/cargo) from the
[rustup](https://rustup.rs/) toolchain installer.

```
cargo build --release
```

## Local Testing

Running regtest node is supported using [Polar](https://lightningpolar.com/):

```
cargo run --bin chamberlaind -- --network=regtest --bitcoind-rpc-url=http://127.0.0.1:18443 --bitcoind-rpc-user=polaruser --bitcoind-rpc-password=polarpass --mint-url=http://<LOCAL_IP_ADDRESS>:3338 --http-host 0.0.0.0 --lightning-port=9634 --log-level=debug
```
