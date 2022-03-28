package wallet

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"
	"log"
	"path/filepath"
	"sort"
)

type leveldbDatabase struct {
	db *leveldb.DB
}

func NewLeveldbMemStorage() (d Database, err error) {

	ldb, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		err = fmt.Errorf("%w: cannot open memory storage leveldb", err)
		return
	}
	//log.Printf("opened wallet db at %v\n", dbFilename)

	d = &leveldbDatabase{db: ldb}
	return
}

func NewLeveldbDatabase(dbDir string) (d Database, err error) {
	if dbDir == "" {

		return NewLeveldbMemStorage()
	}
	dbFilename := filepath.Join(dbDir, "wallet")
	ldb, err := leveldb.OpenFile(dbFilename, nil)
	if err != nil {
		err = fmt.Errorf("%w: cannot open leveldb at %v", err, dbFilename)
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
		return fmt.Errorf("%w: cannot marshal SenderSlate into json", err)
	}

	err = t.db.Put(senderSlateKey(slate.Transaction.ID.String()), slateBytes, nil)
	if err != nil {
		return fmt.Errorf("%w: cannot Put slate", err)
	}

	return nil
}

func receiverSlateKey(id string) []byte {
	return []byte("slate." + id + ".r")
}

func (t *leveldbDatabase) PutReceiverSlate(slate *SavedSlate) error {
	slateBytes, err := json.Marshal(slate)
	if err != nil {
		return fmt.Errorf("%w: cannot marshal ReceiverSlate into json", err)
	}

	err = t.db.Put(receiverSlateKey(slate.Transaction.ID.String()), slateBytes, nil)
	if err != nil {
		return fmt.Errorf("%w: cannot Put slate", err)
	}

	return nil
}

func (t *leveldbDatabase) PutTransaction(transaction SavedTransaction) error {
	transactionBytes, err := json.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("%w: cannot marshal transaction into json", err)
	}

	key := transactionKey(transaction.ID.String())

	err = t.db.Put(key, transactionBytes, nil)
	if err != nil {
		return fmt.Errorf("%w: cannot Put transaction", err)
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

func (t *leveldbDatabase) PutOutput(output SavedOutput) error {
	outputBytes, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("%w: cannot marshal output into json", err)
	}

	err = t.db.Put(outputKey(output.Commit), outputBytes, nil)
	if err != nil {
		return fmt.Errorf("%w: cannot Put output", err)
	}

	return nil
}

func (t *leveldbDatabase) GetSenderSlate(id []byte) (slate *SavedSlate, err error) {
	slateBytes, err := t.db.Get(senderSlateKey(string(id)), nil)
	if err != nil {
		err = fmt.Errorf("%w: cannot Get slate", err)
		return
	}

	slate = &SavedSlate{}

	err = json.Unmarshal(slateBytes, slate)
	if err != nil {
		err = fmt.Errorf("%w: cannot unmarshal slateBytes", err)
		return
	}

	return slate, nil
}

func (t *leveldbDatabase) GetInputs(amount uint64, asset string) (inputs []SavedOutput, change uint64, err error) {
	// collect valid outputs whose amount is less or equal to the amount to send

	outputs := make([]SavedOutput, 0)

	iter := t.db.NewIterator(outputRange(), nil)
	for iter.Next() {
		output := SavedOutput{}
		err = json.Unmarshal(iter.Value(), &output)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: cannot unmarshal output in iterator", err)
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

	inputs = make([]SavedOutput, 0)

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
			return nil, 0, fmt.Errorf("%w: cannot lock input", err)
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
			return nil, fmt.Errorf("%w: cannot unmarshal slate in iterator", err)
		}
		slates = append(slates, slate)
	}

	iter.Release()
	err = iter.Error()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot iterate", err)
	}

	return slates, nil
}

func (t *leveldbDatabase) ListTransactions() (transactions []SavedTransaction, err error) {
	transactions = make([]SavedTransaction, 0)

	iter := t.db.NewIterator(util.BytesPrefix([]byte("transaction")), nil)
	for iter.Next() {
		transaction := SavedTransaction{}
		err = json.Unmarshal(iter.Value(), &transaction)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot unmarshal transaction in iterator", err)
		}
		transactions = append(transactions, transaction)
	}

	iter.Release()
	err = iter.Error()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot iterate", err)
	}

	return transactions, nil
}

func (t *leveldbDatabase) ListOutputs() (outputs []SavedOutput, err error) {
	outputs = make([]SavedOutput, 0)

	iter := t.db.NewIterator(outputRange(), nil)
	for iter.Next() {
		output := SavedOutput{}
		err = json.Unmarshal(iter.Value(), &output)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot unmarshal output in iterator", err)
		}
		outputs = append(outputs, output)
	}

	iter.Release()
	err = iter.Error()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot iterate", err)
	}

	return outputs, nil
}

func (t *leveldbDatabase) GetTransaction(id []byte) (transaction SavedTransaction, err error) {
	transactionBytes, err := t.db.Get(transactionKey(string(id)), nil)
	if err != nil {
		return SavedTransaction{}, fmt.Errorf("%w: cannot Get transaction", err)
	}

	transaction = SavedTransaction{}

	err = json.Unmarshal(transactionBytes, &transaction)
	if err != nil {
		return SavedTransaction{}, fmt.Errorf("%w: cannot unmarshal transactionBytes", err)
	}

	return transaction, nil
}

func (t *leveldbDatabase) GetOutput(commit string) (output SavedOutput, err error) {
	outputBytes, err := t.db.Get(outputKey(commit), nil)
	if err != nil {
		return SavedOutput{}, fmt.Errorf("%w: cannot Get output", err)
	}

	output = SavedOutput{}

	err = json.Unmarshal(outputBytes, &output)
	if err != nil {
		return SavedOutput{}, fmt.Errorf("%w: cannot unmarshal outputBytes", err)
	}

	return output, nil
}

func (t *leveldbDatabase) Confirm(transactionID []byte) error {
	return t.update(transactionID, TransactionConfirmed, OutputSpent, OutputConfirmed)
}

func (t *leveldbDatabase) Cancel(transactionID []byte) error {
	return t.update(transactionID, TransactionCanceled, OutputConfirmed, OutputCanceled)
}

func (t *leveldbDatabase) update(transactionID []byte, transactionStatus TransactionStatus, inputStatus OutputStatus, outputStatus OutputStatus) error {
	tx, err := t.GetTransaction(transactionID)
	if err != nil {
		return fmt.Errorf("%w: cannot GetTransaction", err)
	}

	tx.Status = transactionStatus

	err = t.PutTransaction(tx)
	if err != nil {
		return fmt.Errorf("%w: cannot PutTransaction", err)
	}

	for _, o := range tx.Body.Inputs {
		output, err := t.GetOutput(o.Commit)

		if errors.Is(err, leveldb.ErrNotFound) {
			// not my input
			continue
		}

		if err != nil {
			return fmt.Errorf("%w: cannot GetOutput", err)
		}

		output.Status = inputStatus

		err = t.PutOutput(output)
		if err != nil {
			return fmt.Errorf("%w: cannot PutOutput", err)
		}
	}

	for _, o := range tx.Body.Outputs {
		output, err := t.GetOutput(o.Commit)

		if errors.Is(err, leveldb.ErrNotFound) {
			// not my output
			continue
		}

		if err != nil {
			return fmt.Errorf("%w: cannot GetOutput", err)
		}

		output.Status = outputStatus

		err = t.PutOutput(output)
		if err != nil {
			return fmt.Errorf("%w: cannot PutOutput", err)
		}
	}

	return nil
}

const indexKey = "index"

func (t *leveldbDatabase) NextIndex() (uint32, error) {
	exists, err := t.db.Has([]byte(indexKey), nil)
	if err != nil {
		return 0, fmt.Errorf("%w: cannot check if Has index", err)
	}

	var index uint32 = 0
	var indexBytes = make([]byte, 4)

	if exists {
		indexBytes, err := t.db.Get([]byte(indexKey), nil)
		if err != nil {
			return 0, fmt.Errorf("%w: cannot Get index", err)
		}

		index = binary.BigEndian.Uint32(indexBytes)
		index++
	}

	binary.BigEndian.PutUint32(indexBytes, index)

	err = t.db.Put([]byte(indexKey), indexBytes, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: cannot Put index", err)
	}

	return index, nil
}
