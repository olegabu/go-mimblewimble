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

type ReceiverContext struct {
	Wallet       *multisigwallet.Wallet
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

func CreateMultipartyUTXO(
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
	// Поднять endpoint, принимающий slate-ы
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
	sendToAll(participantsAddresses, "/first", slate)

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
	println("Second exchange:")
	sendToAll(participantsAddresses, "/second", slate)

	// Дождаться получения всех slate-ов
	for len(context.SignedSlates) < len(participantsAddresses)+1 {
		time.Sleep(1)
	}

	// Выполнить третий шаг
	transactionBytes, multipartyOutputCommit, err := w.AggregateMultiparty(context.SignedSlates)
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
		exists, e := rpcClient.CheckOutput(multipartyOutputCommit)
		if e != nil || !exists {
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

	return multipartyOutputCommit, nil
}

func SpendMultipartyUTXO(
	w *multisigwallet.Wallet,
	multipartyOutputCommit string,
	address string,
	amount uint64,
	asset string,
	id uuid.UUID,
	participantsAddresses []string,
	receiverAddress string,
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
	slate, err := w.SpendMultiparty(multipartyOutputCommit, amount, id, address)
	if err != nil {
		err = errors.Wrap(err, "cannot SpendMultiparty")
		return
	}
	context.mu.Lock()
	context.InitialSlates = append(context.InitialSlates, slate)
	context.mu.Unlock()

	// Разослать участникам slate-ы
	println("First exchange:")
	sendToAll(participantsAddresses, "/first", slate)

	// Тот кто отправляет объединенный slate получателю не дожидается его slate-а
	waitingCount := len(participantsAddresses) + 2
	if needBroadcast {
		waitingCount = len(participantsAddresses) + 1
	}

	// Дождаться получения всех slate-ов
	for len(context.InitialSlates) < waitingCount {
		time.Sleep(1)
	}

	if needBroadcast {
		// Объединить slate-ы и отправить их получателю
		combinedSlate, e := w.CombineMultiparty(context.InitialSlates)
		if e != nil {
			err = errors.Wrap(e, "cannot CombineMultiparty")
			return
		}

		fmt.Println("Sending combined slate to receiver:")
		var ok bool
		for !ok {
			resp, e := http.Post("http://"+receiverAddress+"/receive", "application/json", bytes.NewReader(combinedSlate))
			if e != nil || resp.StatusCode != 200 {
				time.Sleep(1)
			} else {
				fmt.Println(address + ": OK")
				ok = true
				receiverSlate, e := ioutil.ReadAll(resp.Body)
				if e != nil {
					err = errors.Wrap(e, "cannot parse receiverSlate")
					return
				}

				context.InitialSlates = append(context.InitialSlates, receiverSlate)
				context.SignedSlates = append(context.SignedSlates, receiverSlate)

				fmt.Println("Sending receiver slate to other participants:")
				sendToAll(participantsAddresses, "/first", receiverSlate)
				sendToAll(participantsAddresses, "/second", receiverSlate)
			}
		}
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
	println("Second exchange:")
	sendToAll(participantsAddresses, "/second", slate)

	// Дождаться получения всех slate-ов
	for len(context.SignedSlates) < len(participantsAddresses)+2 {
		time.Sleep(1)
	}

	// Выполнить третий шаг
	transactionBytes, newMultipartyOutputCommit, err := w.AggregateMultiparty(context.SignedSlates)
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

	// Проверяем, что output пропал из ledger-а
	fmt.Print("Waiting for the output to disappear from the ledger:...")
	rpcClient, e := NewRPCClient(tendermintAddress)
	if e != nil {
		err = errors.Wrap(e, "cannot NewRPCClient")
		return
	}

	outputExistsInLedger := true
	for outputExistsInLedger {
		exists, e := rpcClient.CheckOutput(multipartyOutputCommit)
		if e != nil || exists {
			time.Sleep(1)
		} else {
			outputExistsInLedger = false
			idBytes, _ := id.MarshalText()
			err = w.Confirm(idBytes)
			if err != nil {
				err = errors.Wrap(err, "cannot Confirm")
				return
			}
			fmt.Println("OK")
		}
	}

	return newMultipartyOutputCommit, nil
}

func ReceiveFromMultipartyUTXO(
	w *multisigwallet.Wallet,
	address string,
	amount uint64,
	asset string,
	id uuid.UUID,
	tendermintAddress string,
) (
	outputCommit string,
	err error,
) {
	// Поднять endpoint для получения slate
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

	// Проверяем, что output пропал из ledger-а
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

func sendToAll(addresses []string, action string, slate []byte) {
	for _, address := range addresses {
		var ok bool
		for !ok {
			resp, err := http.Post("http://"+address+action, "application/json", bytes.NewReader(slate))
			if err != nil || resp.StatusCode != 200 {
				time.Sleep(1)
			} else {
				fmt.Println(address + ": OK")
				ok = true
			}
		}
	}
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
