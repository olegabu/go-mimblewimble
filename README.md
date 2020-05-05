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

### Send and receive

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

### Send an invoice and pay it

You can request a payment by creating an invoice and passing it to the payer.
```bash
mw invoice 1
```
The payer can accept the invoice and pay it.
```bash
mw receive slate-send-4ef548ba-31bd-4d03-8954-9884cc907d15.json
```
Upon receipt of the response slate from the payer the payee will finalize to create a transaction, 
just like in the send-receive scenario with the difference that now it is the payee
that finalizes, not the payer.
```bash
mw finalize slate-receive-4ef548ba-31bd-4d03-8954-9884cc907d15.json
mw confirm 4ef548ba-31bd-4d03-8954-9884cc907d15
```

### Issue different assets

When an asset name is omitted the wallet issues tokens of the default asset: currency `¤`.
Tokens of any asset can be issued and tracked separately by giving their asset's name.  

Issue 5 dollar stablecoins and 10 apple commodity tokens.
```bash
mw issue 5 $
mw issue 10 🍎
mw info
```

Similarly, assets of any type can be transferred. 
Issue 5 dollars to yourself; then send, receive, and finalize to transfer of these 5 dollars.
```bash
mw issue 5 $
mw info
mw send 5 $
mw receive slate-send-5d6cf41e-e3f6-474d-9a5c-314d9344012b.json
mw finalize slate-receive-5d6cf41e-e3f6-474d-9a5c-314d9344012b.json
mw confirm tx-5d6cf41e-e3f6-474d-9a5c-314d9344012b
mw info
```

### Exchange assets

You can exchange tokens of one type of asset with another by creating a transaction that combines inputs and outputs of
different assets. This exchange is atomic thus providing a delivery vs payment guarantee.

Sell 2 apples for $1 by creating a transaction where you're sending 2 apples and receiving 1 dollar.
```bash
mw send 2 🍎 1 $
mw receive slate-send-0b925dc8-2ef2-40d8-8c67-bd4eb804a532.json
mw finalize slate-receive-0b925dc8-2ef2-40d8-8c67-bd4eb804a532.json
mw confirm 0b925dc8-2ef2-40d8-8c67-bd4eb804a532
mw info
```

### Validate transactions

You can validate any transaction serialized in [Grin](https://github.com/mimblewimble/grin) format.
```bash
mw validate tx-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw validate 1_grin_repost.json
```

## Demo consensus node and two online wallets

This demonstrates creation of Mimblewimble transactions by wallets of two users: Sender and Receiver 
connected to a consensus network of one Tendermint node which records outputs and validates transactions.

### Consensus node

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

### Sender

Start Sender's wallet in another console to listen for transaction events from the consensus node.
```bash
mw listen
```

Open Sender's wallet in another console.

Issue 1 coin to yourself in the wallet. This will create `issue-1.json` transaction file that needs to be 
 broadcast to the network to get validated and its Coinbase output recorded.
Observe a new `Coinbase` output in Sender's wallet.
```bash
mw init
mw issue 1
mw info
```
Send this new Coinbase output to the consensus node.
```bash
mw broadcast issue-1.json
```
Now this output can be sent. This will create a `slate-send-<transaction uuid>.json`.
Observe the Coinbase output turn from `Confirmed` to `Locked` state in the sender's wallet.
```bash
mw send 1
mw info
```

### Receiver

Open Receiver's wallet in another console. 

If you're running it on the same host specify a separate wallet directory via a `--persist` flag 
or `MW_PERSIST` env variable. 
Observe Receiver's wallet is empty.
```bash
export MW_PERSIST=~/.mw_r
mw init
mw info
```

Start Receiver's wallet in another console in listening mode.
```bash
MW_PERSIST=~/.mw_r mw listen
```

Receive the input from Sender's slate file saved in the same folder. In reality users send slates to each other.  
This will create a `slate-receive-<transaction uuid>.json`.
Observe a new `Unconfirmed` output in Receiver's wallet.
```bash
mw recieve slate-send-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```

### Back to Sender

Return to Sender's wallet console.

Finalize the transaction. This will create a `tx-<transaction uuid>.json`.
```bash
mw finalize slate-receive-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Broadcast this transaction to consensus network to get recorded in the ledger.
```bash
mw broadcast tx-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
```
Observe both Sender's and Receiver's listening wallets get a transaction event and update their databases.
See original Coinbase output turn to `Spent` in Sender's wallet, 
and the new output in the Receiver's turn from `Unconfirmed` to `Confirmed`.

### Queries

Query consensus node for unspent outputs. 
As the results in jsonRPC are base64 encoded, pipe them thru json parser and base64 decoder. 
```bash
# all unspent outputs in the network's ledger 
curl '0.0.0.0:26657/abci_query?path="output"'

# view query results decoded
curl '0.0.0.0:26657/abci_query?path="output"' | jq -r .result.response.value | base64 -d | jq

# query for a specific output
curl '0.0.0.0:26657/abci_query?path="output/09543892a4fd6a712850716ba31dc63f242978a606aaf7d995e8d5e7d0f021762f"' | jq -r .result.response.value | base64 -d | jq
```

Similarly, you can query for kernel excesses of all transactions recorded, and numbers of total coins issued per asset.
```bash
curl '0.0.0.0:26657/abci_query?path="kernel"' | jq -r .result.response.value | base64 -d | jq
curl '0.0.0.0:26657/abci_query?path="asset"' | jq -r .result.response.value | base64 -d | jq
```   

Ask the node to validate integrity of the world state: 
sum all unspent outputs and kernel excesses known to the network, and validate no coins have been minted out of air.
```bash
curl '0.0.0.0:26657/abci_query?path="validate"'
```


