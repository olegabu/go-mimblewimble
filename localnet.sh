#!/bin/bash

v=${1:-4}
network=${2:-mytestnet}

mw tendermint testnet --config ./config-template.toml --v "$v" --o "./$network"

docker network create "$network"

for i in $(seq 0 $(($v-1))); do
  docker rm -f "node$i"
  docker run -d \
  -v "$GOPATH/bin":/root/bin \
  -v "$PWD/$network/node$i":/root/.tendermint \
  --name "node$i" \
  -p "$((26657+i)):26657" \
  --network "$network" \
  alpine:3.7 \
  /root/bin/mw node
done

docker ps