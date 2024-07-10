#!/bin/sh

cargo build --release
cp target/release/chamberlain ~/.local/bin/
cp target/release/chamberlaind ~/.local/bin/