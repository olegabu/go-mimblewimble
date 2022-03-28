package wallet

import (
	"encoding/json"
	"fmt"
	"github.com/tyler-smith/go-bip32"
	"sort"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"

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
		err = fmt.Errorf("%w: cannot create NewWalletWithoutMasterKey", err)
		return
	}

	if !w.masterKeyExists() {
		err = fmt.Errorf("%w: cannot find master key in %v, run init first", err, persistDir)
		return
	}

	_, err = w.InitMasterKey("")
	if err != nil {
		err = fmt.Errorf("%w: cannot InitMasterKey", err)
		return
	}

	return
}

func NewWalletWithoutMasterKey(persistDir string) (w *Wallet, err error) {
	db, err := NewLeveldbDatabase(persistDir)
	if err != nil {
		err = fmt.Errorf("%w: cannot create NewLeveldbDatabase", err)
		return
	}

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = fmt.Errorf("%w: cannot ContextCreate", err)
		return
	}

	w = &Wallet{persistDir: persistDir, db: db, context: context}

	return
}

func (t *Wallet) Close() {
	t.db.Close()
	secp256k1.ContextDestroy(t.context)
}

func (t *Wallet) Send(amount uint64, asset string, receiveAmount uint64, receiveAsset string) (slateBytes []byte, err error) {
	inputs, change, err := t.db.GetInputs(amount, asset)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot GetInputs", err)
	}

	slateBytes, outputs, savedSlate, err := t.NewSlate(amount, 0, asset, change, inputs, receiveAmount, receiveAsset)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot NewSlate", err)
	}

	for _, o := range outputs {
		err = t.db.PutOutput(o)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot PutOutput", err)
		}
	}

	err = t.db.PutSenderSlate(savedSlate)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot PutSlate", err)
	}

	return
}

func (t *Wallet) Respond(inSlateBytes []byte) (outSlateBytes []byte, err error) {
	var inSlate = &Slate{}
	err = json.Unmarshal(inSlateBytes, inSlate)
	if err != nil {
		err = fmt.Errorf("%w: cannot unmarshal json to inSlate", err)
		return
	}

	fee := uint64(inSlate.Fee)

	// my counterparty who sent the inSlate wishes to receive this amount, this is the amount I will send
	amount := uint64(inSlate.ReceiveAmount)
	asset := inSlate.ReceiveAsset

	// my counterparty sends this amount to me, this is the receive amount for me
	receiveAmount := uint64(inSlate.Amount)
	receiveAsset := inSlate.Asset

	inputs, change, err := t.db.GetInputs(amount, asset)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot GetInputs", err)
	}

	outSlateBytes, outputs, savedSlate, err := t.NewResponse(amount, fee, asset, change, inputs, receiveAmount, receiveAsset, inSlate)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot NewReceive", err)
	}

	for _, o := range outputs {
		err = t.db.PutOutput(o)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot PutOutput", err)
		}
	}

	err = t.db.PutReceiverSlate(savedSlate)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot PutReceiverSlate", err)
	}

	//tx := SavedTransaction{
	//	Transaction: savedSlate.Transaction,
	//	Status:      TransactionUnconfirmed,
	//}
	//
	//err = t.db.PutTransaction(tx)
	//if err != nil {
	//	return nil, fmt.Errorf("%w: cannot PutTransaction", err)
	//}

	return
}

func (t *Wallet) Finalize(responseSlateBytes []byte) (txBytes []byte, err error) {
	responseSlate := &Slate{}

	err = json.Unmarshal(responseSlateBytes, responseSlate)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot unmarshal responseSlateBytes", err)
	}

	id, _ := responseSlate.Transaction.ID.MarshalText()

	senderSlate, err := t.db.GetSenderSlate(id)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot GetSlate", err)
	}

	txBytes, tx, err := t.NewTransaction(responseSlate, senderSlate)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot NewTransaction", err)
	}

	err = t.db.PutTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot PutTransaction", err)
	}

	return txBytes, nil
}

func (t *Wallet) Issue(value uint64, asset string) (issueBytes []byte, err error) {
	walletOutput, blind, err := t.newOutput(value, ledger.CoinbaseOutput, asset, OutputConfirmed)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot create output", err)
	}

	// issue kernel excess is a public blind, as input value to an issue is zero: KEI = RI*G + 0*H
	excess, err := secp256k1.Commit(t.context, blind, 0, &secp256k1.GeneratorH)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot create excess", err)
	}

	err = t.db.PutOutput(*walletOutput)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot PutOutput", err)
	}

	ledgerIssue := ledger.Issue{
		Output: walletOutput.Output,
		Asset:  asset,
		Value:  value,
		Kernel: ledger.TxKernel{
			Features: ledger.CoinbaseKernel,
			Excess:   secp256k1.CommitmentString(excess),
		},
	}

	issueBytes, err = json.Marshal(ledgerIssue)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot marshal ledgerIssue to json", err)
	}

	return
}

func (t *Wallet) Info() (string, error) {
	tableString := &strings.Builder{}

	outputs, err := t.db.ListOutputs()
	if err != nil {
		return tableString.String(), fmt.Errorf("%w: cannot ListOutputs", err)
	}

	// sort outputs decreasing by child key index
	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].Index > outputs[j].Index
	})

	outputTable := tablewriter.NewWriter(tableString)
	outputTable.SetHeader([]string{"value", "asset", "status", "features", "commit", "key"})
	outputTable.SetCaption(true, "Outputs")
	outputTable.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, output := range outputs {
		outputTable.Append([]string{strconv.Itoa(int(output.Value)), output.Asset, output.Status.String(), output.Features.String(), output.Commit[0:4], strconv.Itoa(int(output.Index))})
	}
	outputTable.Render()
	tableString.WriteByte('\n')

	slates, err := t.db.ListSlates()
	if err != nil {
		return tableString.String(), fmt.Errorf("%w: cannot ListSlates", err)
	}
	slateTable := tablewriter.NewWriter(tableString)
	slateTable.SetHeader([]string{"id", "send", "receive", "inputs", "outputs"})
	slateTable.SetCaption(true, "Slates")
	slateTable.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, slate := range slates {
		id, _ := slate.Transaction.ID.MarshalText()

		var inputs = ""
		for _, input := range slate.Transaction.Body.Inputs {
			inputs += input.Commit[0:4] + " "
		}
		var outputs = ""
		for _, output := range slate.Transaction.Body.Outputs {
			outputs += output.Commit[0:4] + " "
		}

		send := ""
		s := int(slate.Amount)
		if s != 0 {
			send = strconv.Itoa(s) + " " + slate.Asset
		}

		receive := ""
		r := int(slate.ReceiveAmount)
		if r != 0 {
			receive = strconv.Itoa(r) + " " + slate.ReceiveAsset
		}

		slateTable.Append([]string{string(id), send, receive, inputs, outputs})
	}
	slateTable.Render()
	tableString.WriteByte('\n')

	transactions, err := t.db.ListTransactions()
	if err != nil {
		return tableString.String(), fmt.Errorf("%w: cannot ListTransactions", err)
	}
	transactionTable := tablewriter.NewWriter(tableString)
	transactionTable.SetHeader([]string{"id", "status", "inputs", "outputs"})
	transactionTable.SetCaption(true, "Transactions")
	transactionTable.SetAlignment(tablewriter.ALIGN_CENTER)
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

		transactionTable.Append([]string{string(id), tx.Status.String(), inputs, outputs})
	}
	transactionTable.Render()
	tableString.WriteByte('\n')

	return tableString.String(), nil
}

func (t *Wallet) Print() error {
	s, err := t.Info()
	if err != nil {
		return err
	}
	print(s)
	return nil
}

func (t *Wallet) Confirm(transactionID []byte) error {
	return t.db.Confirm(transactionID)
}

func (t *Wallet) Cancel(transactionID []byte) error {
	return t.db.Cancel(transactionID)
}

func ParseIDFromSlate(slateBytes []byte) (ID []byte, err error) {
	slate := Slate{}
	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot unmarshal slate from json", err)
	}
	id, err := slate.Transaction.ID.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot marshal from uuid", err)
	}
	return id, nil
}
