package wallet

import (
	"encoding/binary"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"log"
	"path/filepath"
	"sort"
)

type leveldbDatabase struct {
	db *leveldb.DB
}

func NewLeveldbDatabase(dbDir string) (d Database, err error) {
	dbFilename := filepath.Join(dbDir, "wallet")

	ldb, err := leveldb.OpenFile(dbFilename, nil)
	if err != nil {
		err = errors.Wrapf(err, "cannot open leveldb at %v", dbFilename)
		return
	}
	//log.Printf("opened wallet db at %v\n", dbFilename)

	d = &leveldbDatabase{db: ldb}
	return
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

func (t *leveldbDatabase) PutSenderSlate(slate *SavedSlate) error {
	slateBytes, err := json.Marshal(slate)
	if err != nil {
		return errors.Wrap(err, "cannot marshal SenderSlate into json")
	}

	err = t.db.Put(senderSlateKey(slate.Transaction.ID.String()), slateBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put slate")
	}

	return nil
}

func receiverSlateKey(id string) []byte {
	return []byte("slate." + id + ".r")
}

func (t *leveldbDatabase) PutReceiverSlate(slate *SavedSlate) error {
	slateBytes, err := json.Marshal(slate)
	if err != nil {
		return errors.Wrap(err, "cannot marshal ReceiverSlate into json")
	}

	err = t.db.Put(receiverSlateKey(slate.Transaction.ID.String()), slateBytes, nil)
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

	key := transactionKey(transaction.ID.String())

	err = t.db.Put(key, transactionBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put transaction")
	}

	return nil
}

func outputKey(commit string) []byte {
	return []byte("output." + commit)
}

func outputRange() *util.Range {
	return util.BytesPrefix([]byte("output."))
}

func transactionKey(id string) []byte {
	return []byte("transaction." + id)
}

func (t *leveldbDatabase) PutOutput(output Output) error {
	outputBytes, err := json.Marshal(output)
	if err != nil {
		return errors.Wrap(err, "cannot marshal output into json")
	}

	err = t.db.Put(outputKey(output.Commit), outputBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put output")
	}

	return nil
}

func (t *leveldbDatabase) GetSenderSlate(id []byte) (slate *SavedSlate, err error) {
	slateBytes, err := t.db.Get(senderSlateKey(string(id)), nil)
	if err != nil {
		err = errors.Wrap(err, "cannot Get slate")
		return
	}

	slate = &SavedSlate{}

	err = json.Unmarshal(slateBytes, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal slateBytes")
		return
	}

	return slate, nil
}

func (t *leveldbDatabase) GetInputs(amount uint64, asset string) (inputs []Output, change uint64, err error) {
	// collect valid outputs whose amount is less or equal to the amount to send

	outputs := make([]Output, 0)

	iter := t.db.NewIterator(outputRange(), nil)
	for iter.Next() {
		output := Output{}
		err = json.Unmarshal(iter.Value(), &output)
		if err != nil {
			return nil, 0, errors.Wrap(err, "cannot unmarshal output in iterator")
		}
		if output.Asset == asset && output.Status == OutputConfirmed {
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

	// lock outputs as they are now inputs to a new transaction

	for _, input := range inputs {
		input.Status = OutputLocked
		err = t.PutOutput(input)
		if err != nil {
			return nil, 0, errors.Wrap(err, "cannot lock input")
		}
	}

	return inputs, change, nil
}

func (t *leveldbDatabase) ListSlates() (slates []SavedSlate, err error) {
	slates = make([]SavedSlate, 0)

	iter := t.db.NewIterator(util.BytesPrefix([]byte("slate")), nil)
	for iter.Next() {
		slate := SavedSlate{}
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

	iter := t.db.NewIterator(outputRange(), nil)
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
	transactionBytes, err := t.db.Get(transactionKey(string(id)), nil)
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

func (t *leveldbDatabase) GetOutput(commit string) (output Output, err error) {
	outputBytes, err := t.db.Get(outputKey(commit), nil)
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
		output, err := t.GetOutput(o.Commit)

		if errors.Cause(err) == leveldb.ErrNotFound {
			// not my input
			continue
		}

		if err != nil {
			return errors.Wrap(err, "cannot GetOutput")
		}

		output.Status = OutputSpent

		err = t.PutOutput(output)
		if err != nil {
			return errors.Wrap(err, "cannot PutOutput")
		}
	}

	for _, o := range tx.Body.Outputs {
		output, err := t.GetOutput(o.Commit)

		if errors.Cause(err) == leveldb.ErrNotFound {
			// not my output
			continue
		}

		if err != nil {
			return errors.Wrap(err, "cannot GetOutput")
		}

		output.Status = OutputConfirmed

		err = t.PutOutput(output)
		if err != nil {
			return errors.Wrap(err, "cannot PutOutput")
		}
	}

	return nil
}

const indexKey = "index"

func (t *leveldbDatabase) NextIndex() (uint32, error) {
	exists, err := t.db.Has([]byte(indexKey), nil)
	if err != nil {
		return 0, errors.Wrap(err, "cannot check if Has index")
	}

	var index uint32 = 0
	var indexBytes = make([]byte, 4)

	if exists {
		indexBytes, err := t.db.Get([]byte(indexKey), nil)
		if err != nil {
			return 0, errors.Wrap(err, "cannot Get index")
		}

		index = binary.BigEndian.Uint32(indexBytes)
		index++
	}

	binary.BigEndian.PutUint32(indexBytes, index)

	err = t.db.Put([]byte(indexKey), indexBytes, nil)
	if err != nil {
		return 0, errors.Wrap(err, "cannot Put index")
	}

	return index, nil
}
