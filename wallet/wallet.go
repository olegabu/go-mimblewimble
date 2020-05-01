package wallet

import (
	"encoding/json"
	"github.com/tyler-smith/go-bip32"
	"os"
	"sort"
	"strconv"

	"github.com/blockcypher/libgrin/core"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
)

type Wallet struct {
	persistDir string
	db         Database
	masterKey  *bip32.Key
	context    *secp256k1.Context
}

func NewWallet(persistDir string) (w *Wallet, err error) {
	w, err = NewWalletWithoutMasterKey(persistDir)
	if err != nil {
		err = errors.Wrap(err, "cannot create NewWalletWithoutMasterKey")
		return
	}

	if !w.masterKeyExists() {
		err = errors.Errorf("cannot find master key in %v, run init first", persistDir)
		return
	}

	_, err = w.InitMasterKey("")
	if err != nil {
		err = errors.Wrap(err, "cannot InitMasterKey")
		return
	}

	return
}

func NewWalletWithoutMasterKey(persistDir string) (w *Wallet, err error) {
	db, err := NewLeveldbDatabase(persistDir)
	if err != nil {
		err = errors.Wrap(err, "cannot create NewLeveldbDatabase")
		return
	}

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot ContextCreate")
		return
	}

	w = &Wallet{persistDir: persistDir, db: db, context: context}

	return
}

func (t *Wallet) Close() {
	t.db.Close()
	secp256k1.ContextDestroy(t.context)
}

func (t *Wallet) Send(amount uint64, asset string) (slateBytes []byte, err error) {
	inputs, change, err := t.db.GetInputs(amount, asset)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slateBytes, changeOutput, senderSlate, err := t.CreateSlate(amount, 0, asset, change, inputs)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateSlate")
	}

	if changeOutput != nil {
		err = t.db.PutOutput(*changeOutput)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutOutput")
		}
	}

	err = t.db.PutSenderSlate(senderSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return
}

func (t *Wallet) Receive(sendSlateBytes []byte) (responseSlateBytes []byte, err error) {
	responseSlateBytes, receiverOutput, receiverSlate, err := t.CreateResponse(sendSlateBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot CreateResponse")
	}

	err = t.db.PutOutput(*receiverOutput)
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

	return
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

	txBytes, tx, err := t.CreateTransaction(responseSlateBytes, senderSlate)
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
	walletOutput, blind, err := t.createOutput(value, core.CoinbaseOutput, asset, OutputConfirmed)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create output")
	}

	excess, err := secp256k1.Commit(t.context, blind, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create excess")
	}

	err = t.db.PutOutput(*walletOutput)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutOutput")
	}

	ledgerIssue := ledger.Issue{
		Output: walletOutput.Output,
		Asset:  asset,
		Kernel: core.TxKernel{
			Features: core.CoinbaseKernel,
			Excess:   excess.String(),
		},
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

	// sort outputs decreasing by child key index
	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].Index > outputs[j].Index
	})

	outputTable := tablewriter.NewWriter(os.Stdout)
	outputTable.SetHeader([]string{"value", "asset", "status", "features", "commit", "key"})
	outputTable.SetCaption(true, "Outputs")
	for _, output := range outputs {
		outputTable.Append([]string{strconv.Itoa(int(output.Value)), output.Asset, output.Status.String(), output.Features.String(), output.Commit[0:4], strconv.Itoa(int(output.Index))})
	}
	outputTable.Render()
	print("\n")

	slates, err := t.db.ListSlates()
	if err != nil {
		return errors.Wrap(err, "cannot ListSlates")
	}
	slateTable := tablewriter.NewWriter(os.Stdout)
	slateTable.SetHeader([]string{"id", "status", "amount", "asset", "inputs", "outputs"})
	slateTable.SetCaption(true, "Slates")
	for _, slate := range slates {
		id, _ := slate.ID.MarshalText()

		var inputs = ""
		for _, input := range slate.Transaction.Body.Inputs {
			inputs += input.Commit[0:4] + " "
		}
		var outputs = ""
		for _, output := range slate.Transaction.Body.Outputs {
			outputs += output.Commit[0:4] + " "
		}

		slateTable.Append([]string{string(id), slate.Status.String(), strconv.Itoa(int(slate.Amount)), slate.Asset, inputs, outputs})
	}
	//slateTable.SetAutoMergeCells(true)
	//slateTable.SetRowLine(true)
	slateTable.Render()
	print("\n")

	transactions, err := t.db.ListTransactions()
	if err != nil {
		return errors.Wrap(err, "cannot ListTransactions")
	}
	transactionTable := tablewriter.NewWriter(os.Stdout)
	transactionTable.SetHeader([]string{"id", "status", "asset", "inputs", "outputs"})
	transactionTable.SetCaption(true, "Transactions")
	for _, tx := range transactions {
		id, _ := tx.ID.MarshalText()

		var inputs = ""
		for _, input := range tx.Transaction.Body.Inputs {
			inputs += input.Commit[0:4] + " "
		}
		var outputs = ""
		for _, output := range tx.Transaction.Body.Outputs {
			outputs += output.Commit[0:4] + " "
		}

		transactionTable.Append([]string{string(id), tx.Status.String(), tx.Asset, inputs, outputs})
	}
	//transactionTable.SetAutoMergeCells(true)
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
