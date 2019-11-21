package wallet

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"log"
	"sort"
)

var dbFilename string

func init() {
	dir, err := homedir.Dir()
	if err != nil {
		panic("cannot get homedir")
	}
	dbFilename = dir + "/.mw/wallet"
}

type leveldbDatabase struct {
	db *leveldb.DB
}

func NewLeveldbDatabase() Database {
	ldb, err := leveldb.OpenFile(dbFilename, nil)
	if err != nil {
		log.Fatalf("cannot open leveldb at %v: %v", dbFilename, err)
	}

	var d Database = &leveldbDatabase{db: ldb}
	return d
}

func (t *leveldbDatabase) Close() {
	err := t.db.Close()
	if err != nil {
		log.Fatal("cannot close leveldb:", err)
	}
}

func senderSlateKey(id string) []byte {
	return []byte("slate." + id + ".s")
}

func (t *leveldbDatabase) PutSenderSlate(slate SenderSlate) error {
	slateBytes, err := json.Marshal(slate)
	if err != nil {
		return errors.Wrap(err, "cannot marshal SenderSlate into json")
	}

	err = t.db.Put(senderSlateKey(slate.ID.String()), slateBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put slate")
	}

	return nil
}

func receiverSlateKey(id string) []byte {
	return []byte("slate." + id + ".r")
}

func (t *leveldbDatabase) PutReceiverSlate(slate ReceiverSlate) error {
	slateBytes, err := json.Marshal(slate)
	if err != nil {
		return errors.Wrap(err, "cannot marshal ReceiverSlate into json")
	}

	err = t.db.Put(receiverSlateKey(slate.ID.String()), slateBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put slate")
	}

	return nil
}

func (t *leveldbDatabase) PutTransaction(transaction Transaction) error {
	transactionBytes, err := json.Marshal(transaction)
	if err != nil {
		return errors.Wrap(err, "cannot marshal transaction into json")
	}

	id, err := transaction.ID.MarshalText()
	if err != nil {
		return errors.Wrap(err, "cannot marshal ID into bytes")
	}

	id = append([]byte("transaction"), id...)

	err = t.db.Put(id, transactionBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put transaction")
	}

	return nil
}

func outputKey(output Output) []byte {
	return []byte("output." + output.Asset + "." + output.Commit)
}

func outputRange(asset string) *util.Range {
	return util.BytesPrefix([]byte("output." + asset))
}

func (t *leveldbDatabase) PutOutput(output Output) error {
	outputBytes, err := json.Marshal(output)
	if err != nil {
		return errors.Wrap(err, "cannot marshal output into json")
	}

	err = t.db.Put(outputKey(output), outputBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put output")
	}

	return nil
}

func (t *leveldbDatabase) GetSenderSlate(id []byte) (slate SenderSlate, err error) {
	slateBytes, err := t.db.Get(senderSlateKey(string(id)), nil)
	if err != nil {
		return SenderSlate{}, errors.Wrap(err, "cannot Get slate")
	}

	slate = SenderSlate{}

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return SenderSlate{}, errors.Wrap(err, "cannot unmarshal slateBytes")
	}

	return slate, nil
}

func (t *leveldbDatabase) GetInputs(amount uint64, asset string) (inputs []Output, change uint64, err error) {
	// collect valid outputs whose amount is less or equal to the amount to send

	outputs := make([]Output, 0)

	iter := t.db.NewIterator(outputRange(asset), nil)
	for iter.Next() {
		output := Output{}
		err = json.Unmarshal(iter.Value(), &output)
		if err != nil {
			return nil, 0, errors.Wrap(err, "cannot unmarshal output in iterator")
		}
		if output.Status == OutputConfirmed {
			outputs = append(outputs, output)
		}
	}

	// sort outputs increasing by value

	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].Value < outputs[j].Value
	})

	// loop thru outputs and collect into inputs only enough to cover the amount

	inputs = make([]Output, 0)

	var sumValues uint64

	for _, output := range outputs {
		sumValues += output.Value
		inputs = append(inputs, output)

		if sumValues >= amount {
			break
		}
	}

	// calculate value of change output

	if sumValues < amount {
		return nil, 0, errors.New("sum of sender input values is less than the amount to send")
	}

	change = sumValues - amount

	// lock outputs as their are inputs now

	for _, input := range inputs {
		input.Status = OutputLocked
		err = t.PutOutput(input)
		if err != nil {
			return nil, 0, errors.Wrap(err, "cannot lock input")
		}
	}

	return inputs, change, nil
}

func (t *leveldbDatabase) ListSlates() (slates []Slate, err error) {
	slates = make([]Slate, 0)

	iter := t.db.NewIterator(util.BytesPrefix([]byte("slate")), nil)
	for iter.Next() {
		slate := Slate{}
		err = json.Unmarshal(iter.Value(), &slate)
		if err != nil {
			return nil, errors.Wrap(err, "cannot unmarshal slate in iterator")
		}
		slates = append(slates, slate)
	}

	iter.Release()
	err = iter.Error()
	if err != nil {
		return nil, errors.Wrap(err, "cannot iterate")
	}

	return slates, nil
}

func (t *leveldbDatabase) ListTransactions() (transactions []Transaction, err error) {
	transactions = make([]Transaction, 0)

	iter := t.db.NewIterator(util.BytesPrefix([]byte("transaction")), nil)
	for iter.Next() {
		transaction := Transaction{}
		err = json.Unmarshal(iter.Value(), &transaction)
		if err != nil {
			return nil, errors.Wrap(err, "cannot unmarshal transaction in iterator")
		}
		transactions = append(transactions, transaction)
	}

	iter.Release()
	err = iter.Error()
	if err != nil {
		return nil, errors.Wrap(err, "cannot iterate")
	}

	return transactions, nil
}

func (t *leveldbDatabase) ListOutputs() (outputs []Output, err error) {
	outputs = make([]Output, 0)

	iter := t.db.NewIterator(outputRange(""), nil)
	for iter.Next() {
		output := Output{}
		err = json.Unmarshal(iter.Value(), &output)
		if err != nil {
			return nil, errors.Wrap(err, "cannot unmarshal output in iterator")
		}
		outputs = append(outputs, output)
	}

	iter.Release()
	err = iter.Error()
	if err != nil {
		return nil, errors.Wrap(err, "cannot iterate")
	}

	return outputs, nil
}

func (t *leveldbDatabase) GetTransaction(id []byte) (transaction Transaction, err error) {
	id = append([]byte("transaction"), id...)

	transactionBytes, err := t.db.Get(id, nil)
	if err != nil {
		return Transaction{}, errors.Wrap(err, "cannot Get transaction")
	}

	transaction = Transaction{}

	err = json.Unmarshal(transactionBytes, &transaction)
	if err != nil {
		return Transaction{}, errors.Wrap(err, "cannot unmarshal transactionBytes")
	}

	return transaction, nil
}

func (t *leveldbDatabase) GetOutput(commit string, asset string) (output Output, err error) {
	o := Output{Output: core.Output{Commit: commit}, Asset: asset}

	outputBytes, err := t.db.Get(outputKey(o), nil)
	if err != nil {
		return Output{}, errors.Wrap(err, "cannot Get output")
	}

	output = Output{}

	err = json.Unmarshal(outputBytes, &output)
	if err != nil {
		return Output{}, errors.Wrap(err, "cannot unmarshal outputBytes")
	}

	return output, nil
}

func (t *leveldbDatabase) Confirm(transactionID []byte) error {
	tx, err := t.GetTransaction(transactionID)
	if err != nil {
		return errors.Wrap(err, "cannot GetTransaction")
	}

	tx.Status = TransactionConfirmed

	err = t.PutTransaction(tx)
	if err != nil {
		return errors.Wrap(err, "cannot PutTransaction")
	}

	for _, o := range tx.Body.Inputs {
		output, err := t.GetOutput(o.Commit, tx.Asset)
		if err != nil {
			return errors.Wrap(err, "cannot GetOutput")
		}

		output.Status = OutputSpent

		err = t.PutOutput(output)
		if err != nil {
			return errors.Wrap(err, "cannot PutTransaction")
		}
	}

	for _, o := range tx.Body.Outputs {
		output, err := t.GetOutput(o.Commit, tx.Asset)
		if err != nil {
			return errors.Wrap(err, "cannot GetOutput")
		}

		output.Status = OutputConfirmed

		err = t.PutOutput(output)
		if err != nil {
			return errors.Wrap(err, "cannot PutTransaction")
		}
	}

	return nil
}
