package wallet

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Output struct {
	core.Output
	Blind [32]byte
	Value uint64
}

type Slate struct {
	libwallet.Slate
	SumSenderBlinds [32]byte
	Nonce           [32]byte
}

type Transaction struct {
	core.Transaction
	ID uuid.UUID
}

type Database interface {
	PutSlate(slate Slate) error
	PutTransaction(tx Transaction) error
	PutOutput(output Output) error

	GetSlate(id []byte) (slate Slate, err error)
	GetTransaction(id []byte) (tx Output, err error)
	ListTransactions() (listTx []core.Transaction, err error)
	ListOutputs() (listSlate []Slate, err error)
	GetEnough(amount uint64) (outputs []Output, err error)
}

type Wallet struct {
	db Database
}

func (t *Wallet) Send(amount uint64) (slateBytes []byte, err error) {
	enoughInputs, err := t.db.GetEnough(amount)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetEnough")
	}

	var sumInputValues uint64
	inputs := make([]Output, 0)

	for _, input := range enoughInputs {
		sumInputValues += input.Value

		inputs = append(inputs, input)

		if sumInputValues >= amount {
			break
		}
	}

	slateBytes, changeOutput, slate, err := CreateSlate(amount, inputs)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateSlate")
	}

	err = t.db.PutOutput(changeOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	err = t.db.PutSlate(slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return slateBytes, nil
}

func (t *Wallet) Receive(slateBytes []byte) (responseSlateBytes []byte, err error) {
	responseSlateBytes, receiverOutput, slate, err := CreateResponse(slateBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateResponse")
	}

	err = t.db.PutOutput(receiverOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	err = t.db.PutSlate(slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return responseSlateBytes, nil
}

func (t *Wallet) Finalize(responseSlateBytes []byte) (txBytes []byte, err error) {
	responseSlate := Slate{}

	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal responseSlateBytes")
	}

	id, _ := responseSlate.ID.MarshalText()

	senderSlate, err := t.db.GetSlate(id)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetSlate")
	}

	txBytes, tx, err := CreateTransaction(responseSlateBytes, senderSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateTransaction")
	}

	err = t.db.PutTransaction(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutTransaction")
	}

	return txBytes, nil
}
