# Chamberlain
> Cashu Mint with Integrated Lightning Node

**Alpha Notice**: The software is currently in alpha-testing. Use at your own risk.

This project aims to substantially increase the number of [Uncle Jims](https://thebitcoinmanual.com/behind-btc/nodes/uncle-jim-node/) running mints who can manage day-to-day Bitcoin transactions for their friends and family.

## Running the Mint

Chamberlain ships with two binaries: `chamberlaind`, the long-running daemon, and `chamberlain`, the management cli tool.

### Unmanaged Mode

Currently, only Chamberlain's unmanaged mode is supported.
This means all DNS, TLS certificate, and firewall configuration will need to be managed by the mint operator.

```
chamberlaind --unmanaged=true --mint-url=http://mint.url:3338
```

## Building from Source

It is recommended to use [cargo](https://github.com/rust-lang/cargo) from the [rustup](https://rustup.rs/) toolchain installer.

```
cargo build --release
```