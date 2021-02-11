package multisigexchange

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/pkg/errors"
)

type ReceiverContext struct {
	Wallet       *wallet.Wallet
	Amount       uint64
	Asset        string
	ID           uuid.UUID
	OutputCommit *string
}

func (context *ReceiverContext) receive(w http.ResponseWriter, req *http.Request) {
	slate, _ := ioutil.ReadAll(req.Body)
	receiverSlate, outputCommit, err := context.Wallet.ReceiveMultiparty(slate, context.Amount, context.Asset, context.ID, "receiver")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = w.Write(receiverSlate)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	context.OutputCommit = &outputCommit
}

func ReceiveFromMultipartyUTXO(
	w *wallet.Wallet,
	address string,
	amount uint64,
	asset string,
	id uuid.UUID,
	tendermintAddress string,
) (
	outputCommit string,
	err error,
) {
	// configure endpoints for exchange slates
	context := ReceiverContext{
		Wallet: w,
		Amount: amount,
		Asset:  asset,
		ID:     id,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/receive", context.receive)
	server := http.Server{Addr: address, Handler: mux}
	go server.ListenAndServe()
	defer server.Close()

	fmt.Print("Waiting for slate...")
	for context.OutputCommit == nil {
		time.Sleep(1)
	}
	fmt.Println("OK")

	fmt.Print("Waiting for the output to appear in the ledger:...")
	rpcClient, e := NewRPCClient(tendermintAddress)
	if e != nil {
		err = errors.Wrap(e, "cannot NewRPCClient")
		return
	}

	outputExistsInLedger := false
	for !outputExistsInLedger {
		exists, e := rpcClient.CheckOutput(*context.OutputCommit)
		if e != nil || !exists {
			time.Sleep(1)
		} else {
			outputExistsInLedger = true
			err = w.ConfirmOutput(*context.OutputCommit)
			if err != nil {
				err = errors.Wrap(err, "cannot ConfirmOutput")
				return
			}
			fmt.Println("OK")
		}
	}
	return *context.OutputCommit, nil
}
