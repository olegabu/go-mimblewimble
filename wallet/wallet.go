package wallet

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/blockcypher/libgrin/core"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"

	"github.com/olegabu/go-mimblewimble/ledger"
	// "github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
)

type Wallet struct {
	db Database
}

func NewWallet(db Database) *Wallet {
	return &Wallet{db: db}
}

func (t *Wallet) Send(amount uint64, asset string) (slateBytes []byte, err error) {
	inputs, change, err := t.db.GetInputs(amount, asset)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slateBytes, changeOutput, senderSlate, err := CreateSlate(nil, amount, 0, asset, change, inputs)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateSlate")
	}

	if change > 0 {
		err = t.db.PutOutput(changeOutput)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutOutput")
		}
	}

	err = t.db.PutSenderSlate(senderSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return slateBytes, nil
}

func (t *Wallet) Receive(slateBytes []byte) (responseSlateBytes []byte, err error) {
	responseSlateBytes, receiverOutput, receiverSlate, err := CreateResponse(slateBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateResponse")
	}

	err = t.db.PutOutput(receiverOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	err = t.db.PutReceiverSlate(receiverSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutReceiverSlate")
	}

	tx := Transaction{
		Transaction: ledger.Transaction{
			Transaction: receiverSlate.Transaction,
			ID:          receiverSlate.ID,
		},
		Status: TransactionUnconfirmed,
		Asset:  receiverSlate.Asset,
	}

	err = t.db.PutTransaction(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutTransaction")
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

	senderSlate, err := t.db.GetSenderSlate(id)
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

func (t *Wallet) Issue(value uint64, asset string) (issueBytes []byte, err error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	blind, _ := secret(context)
	output, walletOutput, err := createOutput(context, blind[:], value, core.CoinbaseOutput, asset, OutputConfirmed)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create output")
	}

	// walletOutput.Status = OutputConfirmed
	// walletOutput.Asset = asset

	err = t.db.PutOutput(*walletOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	ledgerIssue := ledger.Issue{
		Output: *output,
		Asset:  asset,
	}

	issueBytes, err = json.Marshal(ledgerIssue)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal ledgerIssue to json")
	}

	return
}

func (t *Wallet) Info() error {
	outputs, err := t.db.ListOutputs()
	if err != nil {
		return errors.Wrap(err, "cannot ListOutputs")
	}
	outputTable := tablewriter.NewWriter(os.Stdout)
	outputTable.SetHeader([]string{"value", "asset", "status", "features", "commit"})
	outputTable.SetCaption(true, "Outputs")
	for _, output := range outputs {
		outputTable.Append([]string{strconv.Itoa(int(output.Value)), output.Asset, output.Status.String(), output.Features.String(), output.Commit})
	}
	outputTable.Render()
	print("\n")

	slates, err := t.db.ListSlates()
	if err != nil {
		return errors.Wrap(err, "cannot ListSlates")
	}
	slateTable := tablewriter.NewWriter(os.Stdout)
	slateTable.SetHeader([]string{"id", "status", "amount", "asset", "in/out", "features", "commit"})
	slateTable.SetCaption(true, "Slates")
	for _, slate := range slates {
		id, _ := slate.ID.MarshalText()
		for iInput, input := range slate.Transaction.Body.Inputs {
			slateTable.Append([]string{string(id), slate.Status.String(), strconv.Itoa(int(slate.Amount)), slate.Asset, "input " + strconv.Itoa(iInput), input.Features.String(), input.Commit[0:8]})
		}
		for iOutput, output := range slate.Transaction.Body.Outputs {
			slateTable.Append([]string{string(id), slate.Status.String(), strconv.Itoa(int(slate.Amount)), slate.Asset, "output " + strconv.Itoa(iOutput), output.Features.String(), output.Commit[0:8]})
		}
	}
	slateTable.SetAutoMergeCells(true)
	//slateTable.SetRowLine(true)
	slateTable.Render()
	print("\n")

	transactions, err := t.db.ListTransactions()
	if err != nil {
		return errors.Wrap(err, "cannot ListTransactions")
	}
	transactionTable := tablewriter.NewWriter(os.Stdout)
	transactionTable.SetHeader([]string{"id", "status", "asset", "in/out", "features", "commit"})
	transactionTable.SetCaption(true, "Transactions")
	for _, tx := range transactions {
		id, _ := tx.ID.MarshalText()
		for iInput, input := range tx.Body.Inputs {
			transactionTable.Append([]string{string(id), tx.Status.String(), tx.Asset, "input " + strconv.Itoa(iInput), input.Features.String(), input.Commit[0:8]})
		}
		for iOutput, output := range tx.Body.Outputs {
			transactionTable.Append([]string{string(id), tx.Status.String(), tx.Asset, "output " + strconv.Itoa(iOutput), output.Features.String(), output.Commit[0:8]})
		}
	}
	transactionTable.SetAutoMergeCells(true)
	//table.SetRowLine(true)
	transactionTable.Render()
	print("\n")

	return nil
}

func (t *Wallet) Confirm(transactionID []byte) error {
	return t.db.Confirm(transactionID)
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
