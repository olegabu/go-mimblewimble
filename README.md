#  Experimental wallet and library for Mimblewimble protocol

## Build

```bash
go install ./...
```

If you see an error showing the dependent C library was not found:
```
gcc: error: ../../go/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db/secp256k1-zkp/.libs/libsecp256k1.a: No such file or directory
```
You'll have to build it yourself in the directory where `go mod` put `go-secp256k1-zkp` package.
```bash
cd $GOPATH/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db/
```
Fix file and dir permissions there.
```bash
chmod +x secp256k1-zkp/autogen.sh
find . -type d -exec chmod 777 {} \;
```
Install tools and build.
```bash
sudo apt-get install autoconf libtool libgmp3-dev
CFLAGS="-fPIC" make
```

You also may need to tell which repo is private.
```bash
export GOPRIVATE=github.com/olegabu/go-secp256k1-zkp
```

## Run

Reset wallet and ledger (tendermint) databases.
```bash
mw tendermint unsafe_reset_all && rm -rf ~/.mw 
``` 

Start tendermint node with Mimblewimble ABCI application
```bash
mw node
``` 

Run wallet in another console. 

Issue coins to yourself in the wallet.
```bash
mw issue 1
mw info
```
Broadcast new Coinbase outputs to tendermint node.
```bash
mw broadcast tx-issue-1.json
```
Send 1 coin to yourself.
```bash
mw send 1
```
Receive.
```bash
mw recieve slate-send-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
```
Finalize.
```bash
mw finalize slate-receive-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
mw info
```
Broadcast this transaction to tendermint.
```bash
mw broadcast tx-8668319f-d8ae-4dda-be5b-e3fd1648565e.json
```
Tell wallet the transaction has been confirmed by the network.
```bash
mw confirm 8668319f-d8ae-4dda-be5b-e3fd1648565e
mw info
```


