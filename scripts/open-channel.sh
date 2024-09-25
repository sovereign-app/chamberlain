#!/bin/bash

set -e
shopt -s expand_aliases

BITCOIN_CLI=${BITCOIN_CLI:-bitcoin-cli}

NODE_ID=$1
AMOUNT=$2
BTC_AMOUNT=$(echo "scale=8; $AMOUNT / 100000000" | bc | awk '{printf "%.8f", $0}')

# STEP 1: Open a channel with the node
output=$(chamberlain open-channel --node-id $NODE_ID --amount $AMOUNT)
channel_id=$(echo "$output" | awk '/channel id:/ {print $3}')
address=$(echo "$output" | awk '/address:/ {print $2}')
quote_id=$(echo "$output" | awk '/quote id:/ {print $3}')

# STEP 2: Create funding transaction
tx_hex=$($BITCOIN_CLI walletprocesspsbt $($BITCOIN_CLI walletcreatefundedpsbt [] "[{\"$address\":$BTC_AMOUNT}]" | jq -r '.psbt') | jq -r '.hex')

# STEP 3: Fund channel
output=$(chamberlain fund-channel --channel-id $channel_id --tx $tx_hex)
new_channel_id=$(echo "$output" | awk '/channel id:/ {print $3}')

# STEP 4: Mine 3 blocks
new_address=$($BITCOIN_CLI getnewaddress)
for i in 1 2 3
do
  $BITCOIN_CLI generatetoaddress 1 $new_address >/dev/null 2>&1
  sleep 1
done

# STEP 5: Issue channel token
chamberlain issue-channel-token --channel-id $new_channel_id --quote-id $quote_id
