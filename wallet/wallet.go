package wallet

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"os"
	"strconv"
)

type Output struct {
	core.Output
	Blind  [32]byte
	Value  uint64
	Status OutputStatus
}

type OutputStatus int

const (
	New = iota
	Valid
	Locked
	Spent
)

type Slate struct {
	libwallet.Slate
	SumSenderBlinds [32]byte
	Nonce           [32]byte
	Status          SlateStatus
}

type SlateStatus int

const (
	Sent = iota
	Responded
	Finalized
)

type Transaction struct {
	core.Transaction
	ID     uuid.UUID
	Status TransactionStatus
}

type TransactionStatus int

const (
	Unconfirmed = iota
	Confirmed
)

type Database interface {
	PutSlate(slate Slate) error
	PutTransaction(tx Transaction) error
	PutOutput(output Output) error
	GetSlate(id []byte) (slate Slate, err error)
	ListSlates() (slates []Slate, err error)
	ListTransactions() (transactions []Transaction, err error)
	ListOutputs() (outputs []Output, err error)
	GetInputs(amount uint64) (inputs []Output, change uint64, err error)
}

func Send(amount uint64) (slateBytes []byte, err error) {
	inputs, change, err := Db.GetInputs(amount)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slateBytes, changeOutput, slate, err := CreateSlate(amount, change, inputs)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateSlate")
	}

	if change > 0 {
		err = Db.PutOutput(changeOutput)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutOutput")
		}
	}

	err = Db.PutSlate(slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return slateBytes, nil
}

func Receive(slateBytes []byte) (responseSlateBytes []byte, err error) {
	responseSlateBytes, receiverOutput, slate, err := CreateResponse(slateBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateResponse")
	}

	err = Db.PutOutput(receiverOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	err = Db.PutSlate(slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return responseSlateBytes, nil
}

func Finalize(responseSlateBytes []byte) (txBytes []byte, err error) {
	responseSlate := Slate{}

	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal responseSlateBytes")
	}

	id, _ := responseSlate.ID.MarshalText()

	senderSlate, err := Db.GetSlate(id)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetSlate")
	}

	txBytes, tx, err := CreateTransaction(responseSlateBytes, senderSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateTransaction")
	}

	err = Db.PutTransaction(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutTransaction")
	}

	return txBytes, nil
}

func Issue(value uint64) error {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	output, blind, err := output(context, value, core.CoinbaseOutput)
	if err != nil {
		return errors.Wrap(err, "cannot create output")
	}

	walletOutput := Output{
		Output: output,
		Blind:  blind,
		Value:  value,
		Status: Valid,
	}

	err = Db.PutOutput(walletOutput)
	if err != nil {
		return errors.Wrap(err, "cannot PutOutput")
	}

	return nil
}

func Info() error {
	outputs, err := Db.ListOutputs()
	if err != nil {
		return errors.Wrap(err, "cannot ListOutputs")
	}
	outputTable := tablewriter.NewWriter(os.Stdout)
	outputTable.SetHeader([]string{"value", "status", "features", "commit"})
	outputTable.SetCaption(true, "Outputs")
	for _, output := range outputs {
		outputTable.Append([]string{strconv.Itoa(int(output.Value)), strconv.Itoa(int(output.Status)), strconv.Itoa(int(output.Features)), output.Commit})
	}
	outputTable.Render()
	print("\n")

	slates, err := Db.ListSlates()
	if err != nil {
		return errors.Wrap(err, "cannot ListSlates")
	}
	slateTable := tablewriter.NewWriter(os.Stdout)
	slateTable.SetHeader([]string{"id", "status", "amount", "in/out", "features", "commit"})
	slateTable.SetCaption(true, "Slates")
	for _, slate := range slates {
		id, _ := slate.ID.MarshalText()
		for iInput, input := range slate.Transaction.Body.Inputs {
			slateTable.Append([]string{string(id), strconv.Itoa(int(slate.Status)), strconv.Itoa(int(slate.Amount)), "input " + strconv.Itoa(iInput), strconv.Itoa(int(input.Features)), input.Commit})
		}
		for iOutput, output := range slate.Transaction.Body.Outputs {
			slateTable.Append([]string{string(id), strconv.Itoa(int(slate.Status)), strconv.Itoa(int(slate.Amount)), "output " + strconv.Itoa(iOutput), strconv.Itoa(int(output.Features)), output.Commit})
		}
	}
	slateTable.SetAutoMergeCells(true)
	//slateTable.SetRowLine(true)
	slateTable.Render()
	print("\n")

	transactions, err := Db.ListTransactions()
	if err != nil {
		return errors.Wrap(err, "cannot ListTransactions")
	}
	transactionTable := tablewriter.NewWriter(os.Stdout)
	transactionTable.SetHeader([]string{"id", "status", "in/out", "features", "commit"})
	transactionTable.SetCaption(true, "Transactions")
	for _, tx := range transactions {
		id, _ := tx.ID.MarshalText()
		for iInput, input := range tx.Body.Inputs {
			transactionTable.Append([]string{string(id), strconv.Itoa(int(tx.Status)), "input " + strconv.Itoa(iInput), strconv.Itoa(int(input.Features)), input.Commit})
		}
		for iOutput, output := range tx.Body.Outputs {
			transactionTable.Append([]string{string(id), strconv.Itoa(int(tx.Status)), "output " + strconv.Itoa(iOutput), strconv.Itoa(int(output.Features)), output.Commit})
		}
	}
	transactionTable.SetAutoMergeCells(true)
	//table.SetRowLine(true)
	transactionTable.Render()
	print("\n")

	return nil
}
