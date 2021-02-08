package multisigexchange

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/abci"
	"github.com/olegabu/go-mimblewimble/multisigwallet"
	"github.com/pkg/errors"
)

type MultisigContext struct {
	mu            sync.Mutex
	InitialSlates [][]byte
	SignedSlates  [][]byte
}

func (context *MultisigContext) firstExchange(w http.ResponseWriter, req *http.Request) {
	context.mu.Lock()
	slate, _ := ioutil.ReadAll(req.Body)
	context.InitialSlates = append(context.InitialSlates, slate)
	context.mu.Unlock()
}

func (context *MultisigContext) secondExchange(w http.ResponseWriter, req *http.Request) {
	context.mu.Lock()
	slate, _ := ioutil.ReadAll(req.Body)
	context.SignedSlates = append(context.SignedSlates, slate)
	context.mu.Unlock()
}

func CreateMultisigUTXO(
	w *multisigwallet.Wallet,
	address string,
	amount uint64,
	asset string,
	id uuid.UUID,
	participantsAddresses []string,
	tendermintAddress string,
	needBroadcast bool,
) (
	multipartyUtxoCommit string,
	err error,
) {
	// Поднять сервер, принимающий slate-ы
	context := MultisigContext{}
	mux := http.NewServeMux()
	mux.HandleFunc("/first", context.firstExchange)
	mux.HandleFunc("/second", context.secondExchange)
	server := http.Server{Addr: address, Handler: mux}
	go server.ListenAndServe()
	defer server.Close()

	// Осуществить первый шаг
	slate, err := w.FundMultiparty(amount, asset, id, address)
	if err != nil {
		err = errors.Wrap(err, "cannot FundMultiparty")
		return
	}
	context.mu.Lock()
	context.InitialSlates = append(context.InitialSlates, slate)
	context.mu.Unlock()

	// Разослать участникам slate-ы
	println("First exchange:")
	for _, participantAddress := range participantsAddresses {
		var ok bool
		for !ok {
			resp, err := http.Post("http://"+participantAddress+"/first", "application/json", bytes.NewReader(slate))
			if err != nil {
				time.Sleep(1)
			} else if resp.StatusCode != 200 {
				time.Sleep(1)
			} else {
				fmt.Println(participantAddress + ": OK")
				ok = true
			}
		}
	}

	// Дождаться получения всех slate-ов
	for len(context.InitialSlates) < len(participantsAddresses)+1 {
		time.Sleep(1)
	}

	// Выполнить второй шаг
	slate, err = w.SignMultiparty(context.InitialSlates)
	if err != nil {
		err = errors.Wrap(err, "cannot SignMultiparty")
		return
	}
	context.mu.Lock()
	context.SignedSlates = append(context.SignedSlates, slate)
	context.mu.Unlock()

	// Разослать участникам slate-ы
	println("Second exchange")
	for _, participantAddress := range participantsAddresses {
		var ok bool
		for !ok {
			resp, err := http.Post("http://"+participantAddress+"/second", "application/json", bytes.NewReader(slate))
			if err != nil {
				time.Sleep(1)
			} else if resp.StatusCode != 200 {
				time.Sleep(1)
			} else {
				fmt.Println(participantAddress + ": OK")
				ok = true
			}
		}
	}

	// Дождаться получения всех slate-ов
	for len(context.SignedSlates) < len(participantsAddresses)+1 {
		time.Sleep(1)
	}

	// Выполнить третий шаг
	transactionBytes, multipartyOutputCommmit, err := w.AggregateMultiparty(context.SignedSlates)
	if err != nil {
		err = errors.Wrap(err, "cannot AggregateMultiparty")
		return
	}

	// Кто-то из участников броудкастит транзакцию
	if needBroadcast {
		err = broadcast(tendermintAddress, transactionBytes)
		if err != nil {
			err = errors.Wrap(err, "cannot broadcast")
			return
		}
	}

	// Проверяем, что output появился в ledger
	fmt.Print("Waiting for the output to appear in the ledger:...")
	rpcClient, err := NewRPCClient(tendermintAddress)
	if err != nil {
		err = errors.Wrap(err, "cannot NewRPCClient")
		return
	}

	outputExistsInLedger := false
	for !outputExistsInLedger {
		_, err = rpcClient.GetOutput(multipartyOutputCommmit)
		if err != nil {
			time.Sleep(1)
		} else {
			outputExistsInLedger = true
			idBytes, _ := id.MarshalText()
			err = w.Confirm(idBytes)
			if err != nil {
				err = errors.Wrap(err, "cannot Confirm")
				return
			}
			fmt.Println("OK")
		}
	}

	return multipartyOutputCommmit, nil
}

func broadcast(tendermintAddress string, transactionBytes []byte) (err error) {
	client, err := abci.NewClient(tendermintAddress)
	if err != nil {
		return errors.Wrap(err, "cannot NewClient")
	}
	defer client.Stop()

	err = client.Broadcast(transactionBytes)
	if err != nil {
		return errors.Wrap(err, "cannot Broadcast")
	}
	return
}
