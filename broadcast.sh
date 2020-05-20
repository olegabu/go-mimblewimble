curl -d "{\"jsonrpc\":\"2.0\",\"id\":\"anything\",\"method\":\"broadcast_tx_commit\",\"params\": {\"tx\": \"$(base64 -w 0 "$1")\"}}" http://localhost:26657
