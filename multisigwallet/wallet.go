package multisigwallet

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/tyler-smith/go-bip32"

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

func (t *Wallet) Issue(value uint64, asset string) (issueBytes []byte, err error) {
	walletOutput, blind, err := t.newOutput(value, ledger.CoinbaseOutput, asset, OutputConfirmed)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create output")
	}

	// issue kernel excess is a public blind, as input value to an issue is zero: KEI = RI*G + 0*H
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
		Value:  value,
		Kernel: ledger.TxKernel{
			Features: ledger.CoinbaseKernel,
			Excess:   excess.String(),
		},
	}

	issueBytes, err = json.Marshal(ledgerIssue)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal ledgerIssue to json")
	}

	return
}

func (t *Wallet) Info() (string, error) {
	tableString := &strings.Builder{}

	outputs, err := t.db.ListOutputs()
	if err != nil {
		return tableString.String(), errors.Wrap(err, "cannot ListOutputs")
	}

	// sort outputs decreasing by child key index
	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].Index > outputs[j].Index
	})

	outputTable := tablewriter.NewWriter(tableString)
	outputTable.SetHeader([]string{"value", "asset", "status", "features", "commit", "key", "multiparty"})
	outputTable.SetCaption(true, "Outputs")
	outputTable.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, output := range outputs {
		outputTable.Append([]string{strconv.Itoa(int(output.Value)), output.Asset, output.Status.String(), output.Features.String(), output.Commit[0:4], strconv.Itoa(int(output.Index)), strconv.FormatBool(output.IsMultiparty)})
	}
	outputTable.Render()
	tableString.WriteByte('\n')

	slates, err := t.db.ListSlates()
	if err != nil {
		return tableString.String(), errors.Wrap(err, "cannot ListSlates")
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
		return tableString.String(), errors.Wrap(err, "cannot ListTransactions")
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

func ParseIDFromSlate(slateBytes []byte) (ID []byte, err error) {
	slate := Slate{}
	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal slate from json")
	}
	id, err := slate.Transaction.ID.MarshalText()
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal from uuid")
	}
	return id, nil
}

func (t *Wallet) InitFundingTransaction(amount uint64, asset string, id uuid.UUID) (slateBytes []byte, err error) {
	inputs, change, err := t.db.GetInputs(amount, asset)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slateBytes, savedSlate, outputs, err := t.InitMultipartyTransaction(inputs, change, 0, id)
	if err != nil {
		return nil, errors.Wrap(err, "cannot NewMultipartySlate")
	}

	for _, o := range outputs {
		err = t.db.PutOutput(o)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutOutput")
		}
	}

	err = t.db.PutSenderSlate(savedSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return
}

func (t *Wallet) InitSpendingTransaction(multipartyOutputCommit string, payoutValue uint64, id uuid.UUID) (slateBytes []byte, err error) {
	multipartyOutput, err := t.db.GetOutput(multipartyOutputCommit)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slateBytes, savedSlate, outputs, err := t.InitMultipartyTransaction([]SavedOutput{multipartyOutput}, payoutValue, 0, id)
	if err != nil {
		return nil, errors.Wrap(err, "cannot NewMultipartySlate")
	}

	for _, o := range outputs {
		err = t.db.PutOutput(o)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutOutput")
		}
	}

	err = t.db.PutSenderSlate(savedSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutSlate")
	}

	return
}

func (t *Wallet) SignTransaction(slatesBytes [][]byte) (slateBytes []byte, err error) {
	var slates = make([]*Slate, 0)
	for _, slateBytes := range slatesBytes {
		slate := &Slate{}
		err = json.Unmarshal(slateBytes, slate)
		if err != nil {
			err = errors.Wrap(err, "cannot unmarshal json to inSlate")
			return nil, err
		}
		slates = append(slates, slate)
	}

	id, _ := slates[0].Transaction.ID.MarshalText()

	savedSlate, err := t.db.GetSenderSlate(id)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetSlate")
	}

	slateBytes, err = t.SignMultipartyTransaction(slates, savedSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot NewMultipartySlate")
	}

	return
}

func (t *Wallet) AggregateTransaction(slatesBytes [][]byte) (txBytes []byte, multipartyOutputCommit string, err error) {
	var slates = make([]*Slate, 0)
	for _, slateBytes := range slatesBytes {
		slate := &Slate{}
		e := json.Unmarshal(slateBytes, slate)
		if e != nil {
			err = errors.Wrap(e, "cannot unmarshal json to inSlate")
			return
		}
		slates = append(slates, slate)
	}

	id, _ := slates[0].Transaction.ID.MarshalText()

	savedSlate, err := t.db.GetSenderSlate(id)
	if err != nil {
		err = errors.Wrap(err, "cannot GetSenderSlate")
		return
	}

	txBytes, walletTx, multipartyOutput, err := t.AggregateMultipartyTransaction(slates, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregateFundingTransaction")
		return
	}

	err = t.db.PutTransaction(walletTx)
	if err != nil {
		err = errors.Wrap(err, "cannot PutTransaction")
		return
	}

	multipartyOutputCommit = multipartyOutput.Commit
	err = t.db.PutOutput(*multipartyOutput)
	if err != nil {
		err = errors.Wrap(err, "cannot PutOutput")
		return
	}

	return
}

func (t *Wallet) Confirm(transactionID []byte) error {
	return t.db.Confirm(transactionID)
}
