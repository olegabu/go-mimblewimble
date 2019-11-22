package abci

import (
	"fmt"
	"github.com/pkg/errors"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/rpc/client"
	"github.com/tendermint/tendermint/types"
	"time"
)

type Client struct {
	broadcastUrl string
	httpClient   *client.HTTP
}

func NewClient(broadcastUrl string) (*Client, error) {
	httpClient := client.NewHTTP(broadcastUrl, "/websocket")
	err := httpClient.Start()
	if err != nil {
		return nil, errors.Wrap(err, "cannot start websocket http client")
	}
	fmt.Printf("connected to %v\n", broadcastUrl)

	return &Client{
		broadcastUrl: broadcastUrl,
		httpClient:   httpClient,
	}, nil
}

func (t *Client) Stop() error {
	return t.httpClient.Stop()
}

func (t *Client) Broadcast(transactionBytes []byte) error {
	result, err := t.httpClient.BroadcastTxSync(transactionBytes)
	if err != nil {
		return errors.Wrap(err, "cannot broadcast transaction")
	}

	fmt.Printf("broadcast with result code=%v log=%v\n", result.Code, result.Log)

	// and wait for confirmation
	err = t.waitForOneEvent()
	if err != nil {
		return errors.Wrap(err, "cannot waitForOneEvent after broadcast")
	}

	return nil
}

func (t *Client) waitForOneEvent() error {
	const timeoutSeconds = 5

	evt, err := client.WaitForOneEvent(t.httpClient, types.EventTx, timeoutSeconds*time.Second)
	if err != nil {
		return errors.Wrap(err, "cannot WaitForOneEvent")
	}

	t.PrintTxEvent(evt)

	return nil
}

func (t *Client) PrintTxEvent(evt types.TMEventData) {
	txe, ok := evt.(types.EventDataTx)
	if ok {
		fmt.Printf("got EventDataTx: Code=%v Data=%v Log=%v\n", txe.Result.Code, txe.Result.Data, txe.Result.Log)

		for i, event := range txe.Result.Events {
			fmt.Printf("event %v: Type=%v\n", i, event.Type)
			for i, kv := range event.Attributes {
				fmt.Printf("attribute %v: %v=%v\n", i, string(kv.Key), string(kv.Value))
			}
		}
	}
}

func (t *Client) ListenForTxEvents(onEvent func(evt types.TMEventData)) error {
	const timeoutSeconds = 60

	for {
		evt, err := client.WaitForOneEvent(t.httpClient, types.EventTx, timeoutSeconds*time.Second)
		if err != nil {
			if err.Error() == "timed out waiting for event" {
				fmt.Printf("waiting for tx events for the next %v seconds\n", timeoutSeconds)
			} else {
				return errors.Wrap(err, "cannot WaitForOneEvent")
			}
		} else {
			onEvent(evt)
		}
	}
}

func (t *Client) ListenForSuccessfulTxEvents(onTx func(transactionId []byte)) error {
	return t.ListenForTxEvents(func(evt types.TMEventData) {
		txe, ok := evt.(types.EventDataTx)
		if ok {
			if txe.Result.Code == abcitypes.CodeTypeOK {
				fmt.Printf("got EventDataTx: Code=%v Data=%v Log=%v\n", txe.Result.Code, txe.Result.Data, txe.Result.Log)

				for i, event := range txe.Result.Events {
					fmt.Printf("event %v: Type=%v\n", i, event.Type)
					for i, kv := range event.Attributes {
						key := string(kv.Key)
						value := string(kv.Value)
						fmt.Printf("attribute %v: %v=%v\n", i, key, value)

						if event.Type == "transfer" && key == "id" {
							onTx(kv.Value)
						}
					}
				}
			}
		}
	})
}
