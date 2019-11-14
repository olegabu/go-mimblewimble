package wallet

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"os"
	"strconv"
)

type Database interface {
	PutSlate(slate Slate) error
	PutTransaction(tx Transaction) error
	PutOutput(output Output) error
	GetSlate(id []byte) (slate Slate, err error)
	GetTransaction(id []byte) (transaction Transaction, err error)
	GetOutput(id []byte) (output Output, err error)
	ListSlates() (slates []Slate, err error)
	ListTransactions() (transactions []Transaction, err error)
	ListOutputs() (outputs []Output, err error)
	GetInputs(amount uint64) (inputs []Output, change uint64, err error)
	Confirm(transactionID []byte) error
	Close()
}

func Send(amount uint64) (slateBytes []byte, err error) {
	db := NewDatabase()
	defer db.Close()

	inputs, change, err := db.GetInputs(amount)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slateBytes, changeOutput, slate, err := CreateSlate(amount, change, inputs)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateSlate")
	}

	if change > 0 {
		err = db.PutOutput(changeOutput)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutOutput")
		}
	}

	slate.Status = SlateSent
	err = db.PutSlate(slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return slateBytes, nil
}

func Receive(slateBytes []byte) (responseSlateBytes []byte, err error) {
	db := NewDatabase()
	defer db.Close()

	responseSlateBytes, receiverOutput, slate, err := CreateResponse(slateBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateResponse")
	}

	err = db.PutOutput(receiverOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	//slate.Status = SlateResponded
	//err = db.PutSlate(slate)
	//if err != nil {
	//	return nil, errors.Wrap(err, "cannot PutSlate")
	//}

	tx := Transaction{
		Transaction: slate.Transaction,
		ID:          slate.ID,
		Status:      TransactionUnconfirmed,
	}

	err = db.PutTransaction(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutTransaction")
	}

	return responseSlateBytes, nil
}

func Finalize(responseSlateBytes []byte) (txBytes []byte, err error) {
	db := NewDatabase()
	defer db.Close()

	responseSlate := Slate{}

	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal responseSlateBytes")
	}

	id, _ := responseSlate.ID.MarshalText()

	senderSlate, err := db.GetSlate(id)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetSlate")
	}

	txBytes, tx, err := CreateTransaction(responseSlateBytes, senderSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateTransaction")
	}

	err = db.PutTransaction(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutTransaction")
	}

	return txBytes, nil
}

func Issue(value uint64) (txBytes []byte, err error) {
	db := NewDatabase()
	defer db.Close()

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	output, blind, err := output(context, value, core.CoinbaseOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create output")
	}

	walletOutput := Output{
		Output: output,
		Blind:  blind,
		Value:  value,
		Status: OutputConfirmed,
	}

	err = db.PutOutput(walletOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	tx := core.Transaction{
		Offset: "",
		Body: core.TransactionBody{
			Inputs:  nil,
			Outputs: []core.Output{output},
			Kernels: nil,
		},
	}

	txBytes, err = json.Marshal(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal tx to json")
	}

	return
}

func Info() error {
	db := NewDatabase()
	defer db.Close()

	outputs, err := db.ListOutputs()
	if err != nil {
		return errors.Wrap(err, "cannot ListOutputs")
	}
	outputTable := tablewriter.NewWriter(os.Stdout)
	outputTable.SetHeader([]string{"value", "status", "features", "commit"})
	outputTable.SetCaption(true, "Outputs")
	for _, output := range outputs {
		outputTable.Append([]string{strconv.Itoa(int(output.Value)), output.Status.String(), output.Features.String(), output.Commit[0:8]})
	}
	outputTable.Render()
	print("\n")

	slates, err := db.ListSlates()
	if err != nil {
		return errors.Wrap(err, "cannot ListSlates")
	}
	slateTable := tablewriter.NewWriter(os.Stdout)
	slateTable.SetHeader([]string{"id", "status", "amount", "in/out", "features", "commit"})
	slateTable.SetCaption(true, "Slates")
	for _, slate := range slates {
		id, _ := slate.ID.MarshalText()
		for iInput, input := range slate.Transaction.Body.Inputs {
			slateTable.Append([]string{string(id), slate.Status.String(), strconv.Itoa(int(slate.Amount)), "input " + strconv.Itoa(iInput), input.Features.String(), input.Commit[0:8]})
		}
		for iOutput, output := range slate.Transaction.Body.Outputs {
			slateTable.Append([]string{string(id), slate.Status.String(), strconv.Itoa(int(slate.Amount)), "output " + strconv.Itoa(iOutput), output.Features.String(), output.Commit[0:8]})
		}
	}
	slateTable.SetAutoMergeCells(true)
	//slateTable.SetRowLine(true)
	slateTable.Render()
	print("\n")

	transactions, err := db.ListTransactions()
	if err != nil {
		return errors.Wrap(err, "cannot ListTransactions")
	}
	transactionTable := tablewriter.NewWriter(os.Stdout)
	transactionTable.SetHeader([]string{"id", "status", "in/out", "features", "commit"})
	transactionTable.SetCaption(true, "Transactions")
	for _, tx := range transactions {
		id, _ := tx.ID.MarshalText()
		for iInput, input := range tx.Body.Inputs {
			transactionTable.Append([]string{string(id), tx.Status.String(), "input " + strconv.Itoa(iInput), input.Features.String(), input.Commit[0:8]})
		}
		for iOutput, output := range tx.Body.Outputs {
			transactionTable.Append([]string{string(id), tx.Status.String(), "output " + strconv.Itoa(iOutput), output.Features.String(), output.Commit[0:8]})
		}
	}
	transactionTable.SetAutoMergeCells(true)
	//table.SetRowLine(true)
	transactionTable.Render()
	print("\n")

	return nil
}

func Confirm(transactionID []byte) error {
	db := NewDatabase()
	defer db.Close()

	return db.Confirm(transactionID)
}

func ParseIDFromSlate(slateBytes []byte) (ID []byte, err error) {
	slate := Slate{}
	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal slate from json")
	}
	id, err := slate.ID.MarshalText()
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal from uuid")
	}
	return id, nil
}
