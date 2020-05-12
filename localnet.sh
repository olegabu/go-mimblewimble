#!/bin/bash

# number of validator nodes to create
v=${1:-4}
# number of double spending validator nodes
d=${2:-0}
# name of generated config files folder and docker network, allows to run separate tests on the same host
network=${3:-mytestnet}

# generate config files for nodes
mw tendermint testnet --config ./config-template.toml --v "$v" --o "./$network"

docker network create "$network"

# create docker instances for nodes, expose their client ports 26657, map TM_ROOT folder to the generated config,
# map bin folder so we can run mw installed on the host
for i in $(seq 0 $((v-1))); do
  if ((i < d))
    then doublespend="--doublespend"
    else unset doublespend
  fi
  docker rm -f "node$i"
  docker run -d \
  -v "$GOPATH/bin":/root/bin \
  -v "$PWD/$network/node$i":/root/.tendermint \
  --name "node$i" \
  -p "$((26657+i)):26657" \
  --network "$network" \
  alpine:3.7 \
  /root/bin/mw node "$doublespend"
done

docker ps