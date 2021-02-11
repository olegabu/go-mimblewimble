package multisigexchange

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/olegabu/go-mimblewimble/abci"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/pkg/errors"
)

type ParticipantContext struct {
	mu            sync.Mutex
	InitialSlates [][]byte
	SignedSlates  [][]byte
}

func (context *ParticipantContext) firstExchange(w http.ResponseWriter, req *http.Request) {
	context.mu.Lock()
	slate, _ := ioutil.ReadAll(req.Body)
	context.InitialSlates = append(context.InitialSlates, slate)
	context.mu.Unlock()
}

func (context *ParticipantContext) secondExchange(w http.ResponseWriter, req *http.Request) {
	context.mu.Lock()
	slate, _ := ioutil.ReadAll(req.Body)
	context.SignedSlates = append(context.SignedSlates, slate)
	context.mu.Unlock()
}

func CreateMultipartyUTXO(
	w *wallet.Wallet,
	name string,
	address string,
	amount uint64,
	asset string,
	id uuid.UUID,
	participantsAddresses []string,
	tendermintAddress string,
	needBroadcast bool,
	threshold int,
) (
	multipartyUtxoCommit string,
	err error,
) {
	// configure endpoints for exchange slates
	context := ParticipantContext{}
	mux := http.NewServeMux()
	mux.HandleFunc("/first", context.firstExchange)
	mux.HandleFunc("/second", context.secondExchange)
	server := http.Server{Addr: address, Handler: mux}
	go server.ListenAndServe()
	defer server.Close()

	if threshold > len(participantsAddresses)+1 {
		err = errors.New("threshold cannot be greater than total participant's count")
		return
	}

	isMOfNMultiparty := threshold < len(participantsAddresses)+1

	// make first step
	if !isMOfNMultiparty {
		slate, e := w.FundMultiparty(amount, asset, id, address)
		if e != nil {
			err = errors.Wrap(e, "cannot FundMultiparty")
			return
		}
		context.mu.Lock()
		context.InitialSlates = append(context.InitialSlates, slate)
		context.mu.Unlock()

		println("First exchange:")
		sendToAll(participantsAddresses, "/first", slate)
	} else {
		slates, e := w.FundMOfNMultiparty(amount, asset, id, name, len(participantsAddresses)+1, threshold)
		if e != nil {
			err = errors.Wrap(e, "cannot FundMOfNMultiparty")
			return
		}
		context.mu.Lock()
		context.InitialSlates = append(context.InitialSlates, slates[0])
		context.mu.Unlock()

		println("First exchange:")
		sendUniqueToAll(participantsAddresses, "/first", slates[1:])
	}

	// waiting to receive all slates
	for len(context.InitialSlates) < len(participantsAddresses)+1 {
		time.Sleep(1)
	}

	// make second step
	var slate []byte
	if !isMOfNMultiparty {
		slate, err = w.SignMultiparty(context.InitialSlates)
		if err != nil {
			err = errors.Wrap(err, "cannot SignMultiparty")
			return
		}
	} else {
		slate, err = w.SignMOfNMultiparty(context.InitialSlates, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot SignMOfNMultiparty")
			return
		}
	}
	context.mu.Lock()
	context.SignedSlates = append(context.SignedSlates, slate)
	context.mu.Unlock()

	println("Second exchange:")
	sendToAll(participantsAddresses, "/second", slate)

	// waiting to receive all slates
	for len(context.SignedSlates) < len(participantsAddresses)+1 {
		time.Sleep(1)
	}

	// make third step
	var transactionBytes []byte
	var multipartyOutputCommit string
	if !isMOfNMultiparty {
		transactionBytes, multipartyOutputCommit, err = w.AggregateMultiparty(context.SignedSlates)
		if err != nil {
			err = errors.Wrap(err, "cannot AggregateMultiparty")
			return
		}
	} else {
		transactionBytes, multipartyOutputCommit, err = w.AggregateMOfNMultiparty(context.SignedSlates)
		if err != nil {
			err = errors.Wrap(err, "cannot AggregateMOfNMultiparty")
			return
		}
	}

	// one of the participants broadcasts the transaction
	if needBroadcast {
		err = broadcast(tendermintAddress, transactionBytes)
		if err != nil {
			err = errors.Wrap(err, "cannot broadcast")
			return
		}
	}

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
	w *wallet.Wallet,
	multipartyOutputCommit string,
	name string,
	address string,
	amount uint64,
	asset string,
	id uuid.UUID,
	participantsAddresses []string,
	missingParticipantsNames []string,
	receiverAddress string,
	tendermintAddress string,
	needBroadcast bool,
) (
	multipartyUtxoCommit string,
	err error,
) {
	// configure endpoints for exchange slates
	context := ParticipantContext{}
	mux := http.NewServeMux()
	mux.HandleFunc("/first", context.firstExchange)
	mux.HandleFunc("/second", context.secondExchange)
	server := http.Server{Addr: address, Handler: mux}
	go server.ListenAndServe()
	defer server.Close()

	isMOfNMultiparty := missingParticipantsNames != nil && len(missingParticipantsNames) > 0

	// make first step
	var slate []byte
	if !isMOfNMultiparty {
		slate, err = w.SpendMultiparty(multipartyOutputCommit, amount, id, name)
		if err != nil {
			err = errors.Wrap(err, "cannot SpendMultiparty")
			return
		}
	} else {
		slate, err = w.SpendMOfNMultiparty(multipartyOutputCommit, amount, id, name, missingParticipantsNames)
		if err != nil {
			err = errors.Wrap(err, "cannot SpendMOfNMultiparty")
			return
		}
	}

	context.mu.Lock()
	context.InitialSlates = append(context.InitialSlates, slate)
	context.mu.Unlock()

	println("First exchange:")
	sendToAll(participantsAddresses, "/first", slate)

	waitingCount := len(participantsAddresses) + len(missingParticipantsNames) + 2

	// one of the participants combines slates and sends it to the receiver, so he can't wait for all slates
	if needBroadcast {
		waitingCount = len(participantsAddresses) + 1
	}

	// waiting to receive all slates
	for len(context.InitialSlates) < waitingCount {
		time.Sleep(1)
	}

	if needBroadcast {
		if isMOfNMultiparty {
			println("Sending missing parties slates:")
			for _, missingParticipant := range missingParticipantsNames {
				slate, e := w.SpendMissingParty(context.InitialSlates, amount, missingParticipant)
				if e != nil {
					err = errors.Wrap(e, "cannot SpendMissingParty")
					return
				}
				context.mu.Lock()
				context.InitialSlates = append(context.InitialSlates, slate)
				context.mu.Unlock()
				sendToAll(participantsAddresses, "/first", slate)
			}
		}

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
				fmt.Println(receiverAddress + ": OK")
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

	// make second step
	if missingParticipantsNames == nil || len(missingParticipantsNames) == 0 {
		slate, err = w.SignMultiparty(context.InitialSlates)
		if err != nil {
			err = errors.Wrap(err, "cannot SignMultiparty")
			return
		}
	} else {
		slate, err = w.SignMOfNMultiparty(context.InitialSlates, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot SignMOfNMultiparty")
			return
		}
	}
	context.mu.Lock()
	context.SignedSlates = append(context.SignedSlates, slate)
	context.mu.Unlock()

	println("Second exchange:")
	sendToAll(participantsAddresses, "/second", slate)

	if needBroadcast && missingParticipantsNames != nil && len(missingParticipantsNames) > 0 {
		println("Sending missing parties slates:")
		for _, missingParticipant := range missingParticipantsNames {
			slate, e := w.SignMOfNMultiparty(context.InitialSlates, &missingParticipant)
			if e != nil {
				err = errors.Wrap(e, "cannot SignMOfNMultiparty")
				return
			}
			context.mu.Lock()
			context.SignedSlates = append(context.SignedSlates, slate)
			context.mu.Unlock()

			sendToAll(participantsAddresses, "/second", slate)
		}
	}

	// waiting to receive all slates
	for len(context.SignedSlates) < len(participantsAddresses)+len(missingParticipantsNames)+2 {
		time.Sleep(1)
	}

	// make third step
	var transactionBytes []byte
	var newMultipartyOutputCommit string
	if missingParticipantsNames == nil || len(missingParticipantsNames) == 0 {
		transactionBytes, newMultipartyOutputCommit, err = w.AggregateMultiparty(context.SignedSlates)
		if err != nil {
			err = errors.Wrap(err, "cannot AggregateMultiparty")
			return
		}
	} else {
		transactionBytes, newMultipartyOutputCommit, err = w.AggregateMOfNMultiparty(context.SignedSlates)
		if err != nil {
			err = errors.Wrap(err, "cannot AggregateMOfNMultiparty")
			return
		}
	}

	// one of the participants broadcasts the transaction
	if needBroadcast {
		err = broadcast(tendermintAddress, transactionBytes)
		if err != nil {
			err = errors.Wrap(err, "cannot broadcast")
			return
		}
	}

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

func sendUniqueToAll(addresses []string, action string, slates [][]byte) {
	for i, address := range addresses {
		var ok bool
		for !ok {
			resp, err := http.Post("http://"+address+action, "application/json", bytes.NewReader(slates[i]))
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
