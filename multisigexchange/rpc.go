package multisigexchange

import (
	"encoding/json"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/rpc/client"
)

type RPCClient struct {
	httpClient *client.HTTP
}

func NewRPCClient(tendermintAddress string) (*RPCClient, error) {
	httpClient := client.NewHTTP(tendermintAddress, "/websocket")
	err := httpClient.Start()
	if err != nil {
		return nil, err
	}
	return &RPCClient{httpClient}, nil
}

func (client *RPCClient) GetOutputs() ([]ledger.Output, error) {
	response, err := client.httpClient.ABCIQuery("output", nil)
	outputs := make([]ledger.Output, 0)
	err = json.Unmarshal(response.Response.Value, &outputs)
	if err != nil {
		return nil, err
	}
	return outputs, nil
}

func (client *RPCClient) GetOutput(commitment string) (output *ledger.Output, err error) {
	outputs, err := client.GetOutputs()
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetOutputs")
	}

	for _, output := range outputs {
		if output.Commit == commitment {
			return &output, nil
		}
	}
	return nil, errors.Errorf("cannot find output with commitment %v", commitment)
}
