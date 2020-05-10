#!/bin/bash

v=$1
network=${2:-mytestnet}

mw tendermint testnet --config ./config-template.toml --v $v --o "./$network"

docker network create $network

docker rm -f node0
docker run -d --rm -v "$GOPATH/bin":/root/bin -v "$PWD/$network/node0":/root/.tendermint --name node0 --network $network -p 26657:26657 alpine:3.7 /root/bin/mw node

docker rm -f node1
docker run -d --rm -v "$GOPATH/bin":/root/bin -v "$PWD/$network/node1":/root/.tendermint --name node1 --network $network -p 26658:26657 alpine:3.7 /root/bin/mw node

for i in $(seq 2 $(($v-1))); do docker rm -f "node$i"; done
for i in $(seq 2 $(($v-1))); do docker run -d -v "$GOPATH/bin":/root/bin -v "$PWD/$network/node$i":/root/.tendermint --name "node$i" --network $network alpine:3.7 /root/bin/mw node; done

docker ps