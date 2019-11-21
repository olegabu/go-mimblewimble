package abci

import (
	"fmt"
	"github.com/pkg/errors"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/rpc/client"
	"github.com/tendermint/tendermint/types"
	"time"
)

func connect() (httpClient *client.HTTP, err error) {
	broadcastUrl := "tcp://0.0.0.0:26657"
	httpClient = client.NewHTTP(broadcastUrl, "/websocket")
	err = httpClient.Start()
	if err != nil {
		err = errors.Wrap(err, "cannot start websocket http client")
	}
	fmt.Printf("connected to %v\n", broadcastUrl)
	return
}

func Broadcast(transactionBytes []byte) error {
	httpClient, err := connect()
	if err != nil {
		return errors.Wrap(err, "cannot connect")
	}
	defer httpClient.Stop()

	result, err := httpClient.BroadcastTxSync(transactionBytes)
	if err != nil {
		return errors.Wrap(err, "cannot broadcast transaction")
	}

	fmt.Printf("broadcast with result code=%v log=%v\n", result.Code, result.Log)

	// and wait for confirmation
	err = waitForOneEvent(httpClient)
	if err != nil {
		return errors.Wrap(err, "cannot waitForOneEvent")
	}

	return nil
}

func waitForOneEvent(httpClient *client.HTTP) error {
	const timeoutSeconds = 5

	evt, err := client.WaitForOneEvent(httpClient, types.EventTx, timeoutSeconds*time.Second)
	if err != nil {
		return errors.Wrap(err, "cannot WaitForOneEvent")
	}

	PrintTxEvent(evt)

	return nil
}

func PrintTxEvent(evt types.TMEventData) {
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

func ListenForTxEvents(onEvent func(evt types.TMEventData)) error {
	const timeoutSeconds = 60

	httpClient, err := connect()
	if err != nil {
		return errors.Wrap(err, "cannot connect")
	}
	defer httpClient.Stop()

	for {
		evt, err := client.WaitForOneEvent(httpClient, types.EventTx, timeoutSeconds*time.Second)
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

func ListenForSuccessfulTxEvents(onTx func(transactionId []byte)) error {
	return ListenForTxEvents(func(evt types.TMEventData) {
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
