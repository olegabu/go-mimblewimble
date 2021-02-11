package wallet

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
	"github.com/olegabu/go-mimblewimble/wallet/db"
	"github.com/olegabu/go-mimblewimble/wallet/multisig"
	"github.com/olegabu/go-mimblewimble/wallet/transfer"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-mimblewimble/wallet/utils"
	"github.com/olegabu/go-secp256k1-zkp"
)

type Wallet struct {
	persistDir string
	db         db.Database
	masterKey  *bip32.Key
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
	db, err := db.NewLeveldbDatabase(persistDir)
	if err != nil {
		err = errors.Wrap(err, "cannot create NewLeveldbDatabase")
		return
	}

	w = &Wallet{persistDir: persistDir, db: db}

	return
}

func (t *Wallet) Close() {
	t.db.Close()
}

func (t *Wallet) Send(amount uint64, asset string, receiveAmount uint64, receiveAsset string) (slateBytes []byte, err error) {
	inputs, change, err := t.db.GetInputs(amount, asset)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slateBytes, outputs, savedSlate, err := transfer.Initiate(t, amount, 0, asset, change, inputs, receiveAmount, receiveAsset)
	if err != nil {
		return nil, errors.Wrap(err, "cannot NewSlate")
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

func (t *Wallet) Respond(inSlateBytes []byte) (outSlateBytes []byte, err error) {
	var inSlate = &Slate{}
	err = json.Unmarshal(inSlateBytes, inSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal json to inSlate")
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
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	outSlateBytes, outputs, savedSlate, err := transfer.Respond(t, amount, fee, asset, change, inputs, receiveAmount, receiveAsset, inSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot NewReceive")
	}

	for _, o := range outputs {
		err = t.db.PutOutput(o)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutOutput")
		}
	}

	err = t.db.PutReceiverSlate(savedSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutReceiverSlate")
	}

	//tx := SavedTransaction{
	//	Transaction: savedSlate.Transaction,
	//	Status:      TransactionUnconfirmed,
	//}
	//
	//err = t.db.PutTransaction(tx)
	//if err != nil {
	//	return nil, errors.Wrap(err, "cannot PutTransaction")
	//}

	return
}

func (t *Wallet) Finalize(responseSlateBytes []byte) (txBytes []byte, err error) {
	responseSlate := &Slate{}

	err = json.Unmarshal(responseSlateBytes, responseSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal responseSlateBytes")
	}

	id, _ := responseSlate.Transaction.ID.MarshalText()

	senderSlate, err := t.db.GetSenderSlate(id)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetSlate")
	}

	txBytes, tx, err := transfer.Finalize(responseSlate, senderSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot NewTransaction")
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
		err = errors.Wrap(err, "cannot ContextCreate")
		return
	}
	defer secp256k1.ContextDestroy(context)

	walletOutput, blind, err := utils.NewOutput(t, context, value, ledger.CoinbaseOutput, asset, OutputConfirmed)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create output")
	}

	// issue kernel excess is a public blind, as input value to an issue is zero: KEI = RI*G + 0*H
	excess, err := secp256k1.Commit(context, blind, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
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
	outputTable.SetHeader([]string{"value", "asset", "status", "features", "commit", "multiparty"})
	outputTable.SetCaption(true, "Outputs")
	outputTable.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, output := range outputs {
		outputTable.Append([]string{strconv.Itoa(int(output.Value)), output.Asset, output.Status.String(), output.Features.String(), output.Commit[0:4], strconv.FormatBool(output.IsMultiparty)})
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

func (t *Wallet) FundMultiparty(fundingAmount uint64, asset string, transactionID uuid.UUID, participantID string) (slateBytes []byte, err error) {
	inputs, change, err := t.db.GetInputs(fundingAmount, asset)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slate, savedSlate, outputs, err := multisig.Fund(t, fundingAmount, change, 0, asset, inputs, transactionID, participantID)
	if err != nil {
		return nil, errors.Wrap(err, "cannot Fund")
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

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}
	return
}

func (t *Wallet) SpendMultiparty(multipartyOutputCommit string, spendingAmount uint64, transactionID uuid.UUID, participantID string) (slateBytes []byte, err error) {
	multipartyOutput, err := t.db.GetOutput(multipartyOutputCommit)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slate, savedSlate, outputs, err := multisig.Spend(t, spendingAmount, 0, 0, multipartyOutput.Asset, multipartyOutput, transactionID, participantID)
	if err != nil {
		return nil, errors.Wrap(err, "cannot Spend")
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

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) CombineMultiparty(slatesBytes [][]byte) (slateBytes []byte, err error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot ContextCreate")
		return
	}
	defer secp256k1.ContextDestroy(context)

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

	combinedSlate, err := multisig.Combine(context, slates)
	if err != nil {
		return
	}

	slateBytes, err = json.Marshal(combinedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}
	return
}

func (t *Wallet) ReceiveMultiparty(
	inSlateBytes []byte,
	receiveAmount uint64,
	asset string,
	transactionID uuid.UUID,
	participantID string,
) (
	slateBytes []byte,
	outputCommit string,
	err error,
) {
	slate := &Slate{}
	err = json.Unmarshal(inSlateBytes, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal json to inSlate")
		return
	}

	slate, output, err := multisig.Receive(t, receiveAmount, asset, slate, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot Receive")
		return
	}

	err = t.db.PutOutput(*output)
	if err != nil {
		err = errors.Wrap(err, "cannot PutOutput")
		return
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	outputCommit = output.Commit
	return
}

func (t *Wallet) SignMultiparty(slatesBytes [][]byte) (slateBytes []byte, err error) {
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
		return nil, errors.Wrap(err, "cannot GetSenderSlate")
	}

	slate, err := multisig.Sign(slates, savedSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot Sign")
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}
	return
}

func (t *Wallet) AggregateMultiparty(slatesBytes [][]byte) (transactionBytes []byte, multipartyOutputCommit string, err error) {
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

	transaction, walletTx, multipartyOutput, err := multisig.Aggregate(slates, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot Aggregate")
		return
	}

	err = t.db.PutTransaction(walletTx)
	if err != nil {
		err = errors.Wrap(err, "cannot PutTransaction")
		return
	}

	if multipartyOutput != nil {
		multipartyOutputCommit = multipartyOutput.Commit
		err = t.db.PutOutput(*multipartyOutput)
		if err != nil {
			err = errors.Wrap(err, "cannot PutOutput")
			return
		}
	}

	transactionBytes, err = json.Marshal(transaction)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal ledgerTx to json")
		return
	}
	return
}

func (t *Wallet) FundMOfNMultiparty(
	fundingAmount uint64,
	asset string,
	transactionID uuid.UUID,
	participantID string,
	participantsCount int,
	minParticipantsCount int,
) (
	slatesBytes [][]byte,
	err error,
) {
	inputs, change, err := t.db.GetInputs(fundingAmount, asset)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slates, savedSlate, outputs, err := multisig.FundMOfN(
		t,
		fundingAmount,
		change,
		0,
		asset,
		inputs,
		transactionID,
		participantID,
		participantsCount,
		minParticipantsCount)
	if err != nil {
		return nil, errors.Wrap(err, "cannot FundMOfN")
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

	for _, slate := range slates {
		slateBytes, e := json.Marshal(slate)
		if e != nil {
			err = errors.Wrap(e, "cannot marshal slate to json")
			return
		}
		slatesBytes = append(slatesBytes, slateBytes)
	}
	return
}

func (t *Wallet) SpendMOfNMultiparty(
	multipartyOutputCommit string,
	spendingAmount uint64,
	transactionID uuid.UUID,
	participantID string,
	missingParticipantsIDs []string,
) (
	slateBytes []byte,
	err error,
) {
	multipartyOutput, err := t.db.GetOutput(multipartyOutputCommit)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slate, savedSlate, outputs, err := multisig.SpendMOfN(
		t,
		spendingAmount,
		0,
		multipartyOutput.Asset,
		multipartyOutput,
		transactionID,
		participantID,
		missingParticipantsIDs)
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

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) SpendMissingParty(slatesBytes [][]byte, spendingAmount uint64, missingParticipantID string) (slateBytes []byte, err error) {
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
		return nil, errors.Wrap(err, "cannot GetSenderSlate")
	}

	multipartyOutput, err := t.db.GetOutput(savedSlate.Transaction.Body.Inputs[0].Commit)
	if err != nil {
		return nil, errors.Wrap(err, "cannot GetInputs")
	}

	slate, savedSlate, err := multisig.SpendMissingParty(
		t,
		spendingAmount,
		0,
		slates[0].Asset,
		multipartyOutput,
		savedSlate.Transaction.ID,
		missingParticipantID,
		slates)
	if err != nil {
		err = errors.Wrap(err, "cannot constructMissingPartySlate")
		return nil, err
	}

	err = t.db.PutMissingPartySlate(savedSlate, missingParticipantID)
	if err != nil {
		return nil, errors.Wrap(err, "cannot PutMissingPartySlate")
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}
	return
}

func (t *Wallet) SignMOfNMultiparty(slatesBytes [][]byte, missingPartyID *string) (slateBytes []byte, err error) {
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

	var savedSlate *SavedSlate
	if missingPartyID == nil {
		savedSlate, err = t.db.GetSenderSlate(id)
		if err != nil {
			return nil, errors.Wrap(err, "cannot GetSenderSlate")
		}
	} else {
		savedSlate, err = t.db.GetMissingPartySlate(string(id), *missingPartyID)
		if err != nil {
			return nil, errors.Wrap(err, "cannot GetSenderSlate")
		}
	}

	slate, savedSlate, err := multisig.SignMOfN(slates, savedSlate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot signMultipartyTransaction")
	}

	if missingPartyID == nil {
		err = t.db.PutSenderSlate(savedSlate)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutSlate")
		}
	} else {
		err = t.db.PutMissingPartySlate(savedSlate, *missingPartyID)
		if err != nil {
			return nil, errors.Wrap(err, "cannot PutMissingPartySlate")
		}
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}
	return
}

func (t *Wallet) AggregateMOfNMultiparty(slatesBytes [][]byte) (transactionBytes []byte, multipartyOutputCommit string, err error) {
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

	transaction, walletTx, multipartyOutput, err := multisig.AggregateMOfN(slates, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregateFundingTransaction")
		return
	}

	if multipartyOutput != nil {
		multipartyOutputCommit = multipartyOutput.Commit
		err = t.db.PutOutput(*multipartyOutput)
		if err != nil {
			err = errors.Wrap(err, "cannot PutOutput")
			return
		}
	}

	err = t.db.PutTransaction(walletTx)
	if err != nil {
		err = errors.Wrap(err, "cannot PutTransaction")
		return
	}

	transactionBytes, err = json.Marshal(transaction)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal ledgerTx to json")
		return
	}
	return
}

func (t *Wallet) Confirm(transactionID []byte) error {
	return t.db.Confirm(transactionID)
}

func (t *Wallet) Cancel(transactionID []byte) error {
	return t.db.Cancel(transactionID)
}

func (t *Wallet) ConfirmOutput(commit string) error {
	output, err := t.db.GetOutput(commit)
	if err != nil {
		return errors.Wrap(err, "cannot GetOutput")
	}

	output.Status = OutputConfirmed
	err = t.db.PutOutput(output)
	if err != nil {
		return errors.Wrap(err, "cannot PutOutput")
	}
	return nil
}
