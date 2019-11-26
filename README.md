#  Experimental wallet and library for Mimblewimble protocol

This is a toy. Do not use for production.

## Build

Install tools and build.
```bash
sudo apt-get install autoconf libtool libgmp3-dev
make
```

## Run offline wallet

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
fill in by `mw receive` command. Observe a new `Sent` slate and the input that is now in `Locked` state in your wallet 
by `mw info` command.
```bash
mw send 1
mw info
```
Receive 1 coin from yourself. This will create a `slate-receive-<transaction uuid>.json` file that needs to be returned 
to the sender who will turn it into a transaction by `mw finalize` command. 
Observe new `Unconfirmed` outputs and `Responded` slate in your wallet by `mw info` command.
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
in your wallet by `mw info` command.
```bash
mw confirm 8668319f-d8ae-4dda-be5b-e3fd1648565e
mw info
```

## Run consensus node and two online wallets

Reset wallet and ledger (tendermint) databases.
```bash
mw tendermint unsafe_reset_all && rm -rf ~/.mw*
``` 

Start tendermint consensus node with Mimblewimble ABCI application.
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


