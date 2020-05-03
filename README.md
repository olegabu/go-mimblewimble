#  Experimental wallet and library for Mimblewimble

This is a toy. Do not use for production.

## Prerequisites

Install Golang ([instructions](https://github.com/golang/go/wiki/Ubuntu)).
```bash
sudo add-apt-repository ppa:longsleep/golang-backports && \
sudo apt-get update && \
sudo apt-get install golang-go && \

echo "export GOPATH=~/go" >> ~/.bashrc && \
echo "export PATH=$PATH:~/go/bin" >> ~/.bashrc && \
. ~/.bashrc
```

Install tools.
```bash
sudo apt-get install autoconf libtool libgmp3-dev
```

## Build and test

```bash
go install ./...

go test -v ./wallet ./ledger
```

## Demo offline wallet

This demonstrates creation and validation of Mimblewimble transactions by the wallet.

Cleanup: delete wallet databases (careful! demo and tests only).
```bash
rm -rf ~/.mw*
``` 

Create user's master secret key in the wallet. This will also print out a mnemonic you can use to recover your key.
```bash
mw init
```

Issue coins to yourself in the wallet. Observe new `Coinbase` outputs in your wallet by `mw info` command.
```bash
mw issue 1
mw info
```
Send 1 coin to yourself. This will create a `slate-send-<transaction uuid>.json` file that the receiving party needs to 
fill in by `mw receive` command. Observe a new `Sent` slate and the input that is now in `Locked` state in your wallet.
```bash
mw send 1
mw info
```
Receive 1 coin from yourself. This will create a `slate-receive-<transaction uuid>.json` file that needs to be returned 
to the sender who will turn it into a transaction by `mw finalize` command. 
Observe new `Unconfirmed` outputs and a new `Responded` slate.
```bash
mw receive slate-send-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Finalize the transaction. This will create a `tx-<transaction uuid>.json` file that needs to be broadcast 
to the network to get validated. 
In this offline scenario we'll skip this part and tell the wallet the transaction has been confirmed. 
```bash
mw finalize slate-receive-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Tell our wallet the transaction has been confirmed by the network. 
Observe new `Confirmed` outputs and a new transaction, as well as the input turned from `Locked` to `Spent` 
in your wallet.
```bash
mw confirm 8668319f-d8ae-4dda-be5b-e3fd1648565e
mw info
```

You can request a payment by creating an invoice and passing it to the payer.
```bash
mw invoice 1
```
The payer can accept the invoice and pay it.
```bash
mw pay slate-invoice-4ef548ba-31bd-4d03-8954-9884cc907d15.json
```
Upon receipt of the pay slate from the payer the payee will finalize the exchange to create a transaction, 
just like in the send-receive scenario with the difference that now it is the payee
that finalizes, not the payer.
```bash
mw finalize slate-pay-4ef548ba-31bd-4d03-8954-9884cc907d15.json
mw confirm 4ef548ba-31bd-4d03-8954-9884cc907d15
```

You can validate any transaction serialized in [Grin](https://github.com/mimblewimble/grin) format.
```bash
mw validate tx-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw validate 1_grin_repost.json
```

## Demo consensus node and two online wallets

This demonstrates creation of Mimblewimble transactions by sender's and receiver's wallets connected to a consensus network of one Tendermint node that validates transactions.

If running for the first time generate Tendermint keys.
```bash
mw tendermint init
```
Clean up: delete wallets and reset Tendermint ledger.
```bash
mw tendermint unsafe_reset_all && rm -rf ~/.mw*
```
Start Tendermint consensus node with a built in Mimblewimble ABCI application.
```bash
mw node
```

Start sender's wallet in another console listening for `transfer` transaction events from the consensus node.

```bash
mw listen
```
Start receiver's wallet in another console in listening mode.
If you're running it on the same machine specify a separate database directory via a `--persist` flag 
or `MW_PERSIST` env variable. 
```bash
MW_PERSIST=~/.mw_r mw listen
```

Open sender's wallet in another console.

Issue 1 coin to yourself in the wallet. This will create `issue-1.json` transaction file that needs to be 
 broadcast to the network to get validated and its Coinbase output recorded.
Observe a new `Coinbase` output in the sender's wallet.
```bash
mw init
mw issue 1
mw info
```
Send this new Coinbase output to the consensus node. 
Observe both listening wallets receive `issue` event from the blockchain node.
```bash
mw broadcast issue-1.json
```
Now this output can be sent. This will create a `slate-send-<transaction uuid>.json`.
Observe the Coinbase output turn from `Confirmed` to `Locked` state in the sender's wallet.
```bash
mw send 1
```

Open the receiver's wallet in another console. 

Note that a separate persist directory needs to be set for the receiver.
Observe receiver's wallet is empty.
```bash
export MW_PERSIST=~/.mw_r
mw init
mw info
```
Receive the input from the slate saved by the sender. 
This will create a `slate-receive-<transaction uuid>.json`.
Observe a new `Unconfirmed` output in the receiver's wallet.
```bash
mw recieve slate-send-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```

Return to the sender's wallet console.

Finalize the transaction. This will create a `tx-<transaction uuid>.json`.
```bash
mw finalize slate-receive-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Broadcast this transaction to the network to get recorded in the ledger.
```bash
mw broadcast tx-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
```
Observe both the sender's, and the receiver's online wallets receive transfer event and update their databases.
See original Coinbase output turn to `Spent` in the sender's wallet, 
and the output in the receiver's turn from `Unconfirmed` to `Confirmed`.

Query consensus node for the unspent outputs. 
As the results in jsonRPC are base64 encoded, pipe them thru a json parser and base64 decoder. 
```bash
# all unspent outputs in the network's ledger 
curl '0.0.0.0:26657/abci_query?path="output"'

# view query results decoded
curl '0.0.0.0:26657/abci_query?path="output"' | jq -r .result.response.value | base64 -d | jq

# query for a specific output
curl '0.0.0.0:26657/abci_query?path="output/09543892a4fd6a712850716ba31dc63f242978a606aaf7d995e8d5e7d0f021762f"' | jq -r .result.response.value | base64 -d | jq
```

Similarly, query for kernel excesses of all transactions recorded and numbers of total coins issued per asset.
```bash
curl '0.0.0.0:26657/abci_query?path="kernel"' | jq -r .result.response.value | base64 -d | jq
curl '0.0.0.0:26657/abci_query?path="asset"' | jq -r .result.response.value | base64 -d | jq
```   

Ask the node to validate integrity of the world state: 
sum all unspent outputs and kernel excesses known to the network, and validate no coins have been minted out of air.
```bash
curl '0.0.0.0:26657/abci_query?path="validate"'
```

## Issue multiple assets

When an asset name is omitted the wallet issues a default asset: currency `¤`.
Tokens of any asset can be issued and tracked separately by giving their asset's name.  

Issue a stablecoin of 1 dollar and a commodity token of an apple.
```bash
mw issue 1 $
mw issue 1 🍎
mw info
```

Similarly, assets of any type can be transferred. 
Issue 5 dollars and broadcast it; then send, receive, finalize and broadcast a transfer of these 5 dollars.
```bash
mw issue 5 $
mw broadcast issue-5.json
mw info
mw send 5 $
mw receive slate-send-5d6cf41e-e3f6-474d-9a5c-314d9344012b.json
mw finalize slate-receive-5d6cf41e-e3f6-474d-9a5c-314d9344012b.json
mw broadcast tx-5d6cf41e-e3f6-474d-9a5c-314d9344012b.json
mw info
```

