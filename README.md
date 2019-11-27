#  Experimental wallet and library for Mimblewimble

This is a toy. Do not use for production.

## Build

Install Golang ([instructions](https://github.com/golang/go/wiki/Ubuntu)).
```bash
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt-get update
sudo apt-get install golang-go

echo "export GOPATH=~/go" >> ~/.bashrc
echo "export GOBIN=~/go/bin" >> ~/.bashrc
echo "export PATH=$PATH:$GOBIN" >> ~/.bashrc
. ~/.bashrc
```

Install tools.
```bash
sudo apt-get install autoconf libtool libgmp3-dev
```

## Build

```bash
export GOPRIVATE=github.com/olegabu/go-secp256k1-zkp
make
```

## Demo offline wallet

This demonstrates creation and validation of transactions by the wallet.

Delete wallet databases (careful! demo and tests only).
```bash
rm -rf ~/.mw*
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
Observe new `Unconfirmed` outputs and `Responded` slate in your wallet.
```bash
mw receive slate-send-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Finalize the transaction. This will create a `tx-<transaction uuid>.json` file that needs to be broadcast 
to the network to be validated. 
In this offline scenario we'll skip this part and tell the wallet the transaction has been confirmed. 
```bash
mw finalize slate-receive-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Tell wallet the transaction has been confirmed by the network. 
Observe new `Confirmed` outputs and a new transaction, as well as the input turned from `Locked` to `Spent` 
in your wallet.
```bash
mw confirm 8668319f-d8ae-4dda-be5b-e3fd1648565e
mw info
```

## Demo consensus node and two online wallets

If running for the first time generate Tendermint keys.
```bash
mw tendermint init
```

To clean up reset wallet and ledger (Tendermint) databases.
```bash
mw tendermint unsafe_reset_all && rm -rf ~/.mw*
``` 

Start Tendermint consensus node with Mimblewimble ABCI application.
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
```bash
mw issue 1
mw info
```
Send this new Coinbase output to the consensus node.
```bash
mw broadcast issue-1.json
```
Now this output can be sent. This will create a `slate-send-<transaction uuid>.json`.
```bash
mw send 1
```

Open receiver's wallet in another console. 

Note that a separate persist directory needs to be set.
Receiver's wallet is empty.
```bash
export MW_PERSIST=~/.mw_r
mw info
```
Receive the input. This will create a `slate-receive-<transaction uuid>.json`.
```bash
mw recieve slate-send-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
```

Return to the sender's wallet console.

Finalize the transaction. This will create a `tx-<transaction uuid>.json`.
```bash
mw finalize slate-receive-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Broadcast this transaction to the network.
```bash
mw broadcast tx-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
```
Observe both sender's and receiver's online wallets receive transfer event and update their databases.
See original Coinbase output turn to `Spent` in the sender's wallet, and a new `Confirmed` output in the receiver's.

## Issue multiple assets

When an asset name is omitted the wallet issues a default asset: currency `¤`.
Tokens of any asset can be issued and tracked separately by giving the asset's name.  

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

