#  An experimental wallet and library for Mimblewimble

This is a toy. Do not use in anything serious (yet).

* [Prerequisites](#prerequisites)
* [Build and test](#build-and-test)
* [Demo offline wallet](#demo-offline-wallet)
    + [Send and receive](#send-and-receive)
    + [Send an invoice and pay it](#send-an-invoice-and-pay-it)
    + [Issue different assets](#issue-different-assets)
    + [Exchange assets](#exchange-assets)
    + [Validate transactions](#validate-transactions)
* [Demo consensus node and two online wallets](#demo-consensus-node-and-two-online-wallets)
* [Local test network](#local-test-network)
    + [Crash Fault Tolerance](#crash-fault-tolerance)
    + [Byzantine Fault Tolerance](#byzantine-fault-tolerance)

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
go install -ldflags "-linkmode external -extldflags -static" ./...

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
fill in by `mw receive` command. Observe a new slate and the input that is now in `Locked` state in your wallet.
```bash
mw send 1
mw info
```
Receive 1 coin from yourself. This will create a `slate-receive-<transaction uuid>.json` file that needs to be returned 
to the sender who will turn it into a transaction by `mw finalize` command. 
Observe new `Unconfirmed` outputs, and a new response slate.
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
mw init
mw listen
```

Open Sender's wallet in another console.

Issue 1 coin to yourself in the wallet. This will create `issue-1.json` transaction file that needs to be 
 broadcast to the network to get validated and its Coinbase output recorded.
Observe a new `Coinbase` output in Sender's wallet.
```bash
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

If you're running it on the same host specify a separate wallet directory via `--persist` flag 
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

Receive an input from Sender's slate file saved in the same folder. In reality users send slates to each other.  
This will create a `slate-receive-<transaction uuid>.json`.
Observe a new `Unconfirmed` output in Receiver's wallet.
```bash
mw recieve slate-send-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```

### Back to Sender to finalize

Return to Sender's wallet console.

Post the transaction: finalize to create a `tx-<transaction uuid>.json` 
and broadcast it to consensus network to get recorded in the ledger.
```bash
mw post slate-receive-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Observe both Sender's and Receiver's listening wallets get a transaction event and update their databases.
See original Coinbase output turn to `Spent` in Sender's wallet, 
and the new output in the Receiver's turn from `Unconfirmed` to `Confirmed`.

### Queries

You can query the consensus node for unspent outputs. 
 
```bash
# all unspent outputs in the network's ledger 
curl '0.0.0.0:26657/abci_query?path="output"'

# as the results in jsonRPC are base64 encoded, pipe them thru json parser and base64 decoder
curl '0.0.0.0:26657/abci_query?path="output"' | jq -r .result.response.value | base64 -d | jq

# query for a specific output by its commit
curl '0.0.0.0:26657/abci_query?path="output/09543892a4fd6a712850716ba31dc63f242978a606aaf7d995e8d5e7d0f021762f"' | jq -r .result.response.value | base64 -d | jq
```

Similarly, you can query for kernel excesses of all transactions recorded, and total tokens issued per asset.
```bash
curl '0.0.0.0:26657/abci_query?path="kernel"' | jq -r .result.response.value | base64 -d | jq
curl '0.0.0.0:26657/abci_query?path="asset"' | jq -r .result.response.value | base64 -d | jq
```   

Ask the node to validate integrity of the world state: 
sum all unspent outputs and kernel excesses known to the network, and validate no coins have been minted out of air.
```bash
curl '0.0.0.0:26657/abci_query?path="validate"'
```

## Local test network

Create a consensus network of validating nodes in docker containers on a local host.

### Crash Fault Tolerance

This demo will demonstrate tolerance to some nodes going offline. With the minimum of 4 nodes the network will
continue to operate normally with 1 failed node: `3f+1=4`. 

#### Create

Create a network called `mytestnet` of the minimum 4 nodes required for BFT consensus. 
To create more nodes, or a different network, pass arguments, ex.: `./localnet.sh 31 0 test2`. 
```bash
./localnet.sh
``` 
In this script `mw tendermint testnet` generates node config files in `mytestnet` folder, 
then `docker run` commands create containers out of a standard Linux image with folders mapped to the
generated configs and the folder where `mw` is installed, and run them with `mw node`.

#### Sender

The first user Sender creates his wallet on the host in the default `~/.mw` folder and connects to `node0`
at the default address `tcp://0.0.0.0:26657`.

Connect to the node to listen for events.
```bash
mw init
mw listen
```

Open another console and issue and send `apple` commodity tokens.
```bash
mw issue 10 apple
mw broadcast issue-10.json
mw send 1 apple
```

#### Receiver

User Receiver creates his wallet in `~/.mw_r` folder and connects to `node2` at `tcp://0.0.0.0:26659`.
Note the client port 26657 maps to host's 26659.

Connect to the node to listen for events.
```bash
export MW_PERSIST=~/.mw_r
export MW_ADDRESS=tcp://0.0.0.0:26659
mw init
mw listen
```

Open another console and receive the transfer.
```bash
export MW_PERSIST=~/.mw_r
export MW_ADDRESS=tcp://0.0.0.0:26659
mw receive slate-send-3e722a37-f6a3-46a1-8e7b-c67000ddc666.json 
```

#### Back to Sender to finalize

Sender finalizes and broadcasts the transaction.
```bash
mw post slate-receive-3e722a37-f6a3-46a1-8e7b-c67000ddc666.json
```

Observe in the listening consoles a `transfer` event from node0 update Sender's wallet,
and the Receiver's from the event received from node2. 

Issue more tokens and observe `issue` events in both listening consoles: 
the network validates and propagates transactions. 
```bash
mw issue 1 $ && mw broadcast issue-1.json
```

#### Fail nodes

Now pause one container to reduce the consensus to 3 nodes and observe the events still
propagate thru the network to the listening wallets.
```bash
docker pause node1
mw issue 1 $ && mw broadcast issue-1.json
```

Pause another container and observe the events no longer propagate as the number of failed
nodes 2 exceed BFT threshold `3f+1` for 4 nodes.
```bash
docker pause node3
mw issue 1 orange && mw broadcast issue-1.json
```

Bring back at least one failed node and see the network recover and validate 
and propagate missed transactions.
```bash
docker unpause node3
``` 

### Byzantine Fault Tolerance

We can run some nodes in a mode where they will be double spending inputs thus exhibiting 
byzantine behaviour. This demo will demonstrate tolerance to at least one such node with 4 nodes in the network. 

#### Create

Delete config files and wallets from the previous demo then create a network of 4 nodes out of which 1 will double spend. 
```bash
sudo rm -rf mytestnet/ ~/.mw*
./localnet.sh 4 1 
``` 

#### Sender

Issue and send `apple` commodity tokens.
```bash
mw issue 1 apple
mw broadcast issue-1.json
mw send 1 apple
```

#### Receiver

Connect to node2 to listen for events.
```bash
export MW_PERSIST=~/.mw_r
export MW_ADDRESS=tcp://0.0.0.0:26659
mw init
mw listen
```

Open another console and receive the transfer.
```bash
export MW_PERSIST=~/.mw_r
export MW_ADDRESS=tcp://0.0.0.0:26659
mw receive slate-send-3e722a37-f6a3-46a1-8e7b-c67000ddc666.json 
```

#### Back to Sender to finalize

Sender finalizes and broadcasts the transaction.
```bash
mw post slate-receive-3e722a37-f6a3-46a1-8e7b-c67000ddc666.json
```

Observe in the listening console a `transfer` event from node2 update Receiver's wallet. 

#### Attempt to double spend

Now cancel the transaction we posted: this is a local operation in Sender's wallet that will let us use the inputs
we just spent again. Observe `apple` output turn to `Confirmed` and send this output again.   
```bash
mw cancel 3e722a37-f6a3-46a1-8e7b-c67000ddc666
mw info 
mw send 1 apple
```

In Receiver's console accept the new slate.
```bash
mw receive slate-send-2ce5a045-2678-4f5d-bb0f-fa5f2139deed.json
```

Back in Sender's console post the new transaction.
```bash
mw post slate-receive-2ce5a045-2678-4f5d-bb0f-fa5f2139deed.json
```

Sender broadcast to node0 which is the malicious one, so it accepted the double spending transaction. 
However, the other 3 nodes voted against it so you won't see the transaction event propagate and Receiver's wallet update.

#### More double spending nodes

Let's recreate the network with 2 double spending nodes.
```bash
sudo rm -rf mytestnet/ ~/.mw*
./localnet.sh 4 2 
```

Repeat the above exercise of sending, canceling and sending again. 
Observe no events propagate: the consensus is split between 2 correct and 2 malicious nodes.

Recreate the network with 3 double spending nodes out of 4.
```bash
sudo rm -rf mytestnet/ ~/.mw*
./localnet.sh 4 3
```

Repeat the above exercise but this time succeed in spending the input twice: the correct node is now in the minority.

 



