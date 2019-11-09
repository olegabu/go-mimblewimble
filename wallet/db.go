package wallet

import (
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/crypto/blake2b"
	"log"
	"os/user"
	"sort"
)

var Db Database

type leveldbDatabase struct {
	db *leveldb.DB
}

func init() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal("cannot get current user for home dir:", err)
	}

	ldb, err := leveldb.OpenFile(usr.HomeDir+"/.mw/wallet", nil)
	if err != nil {
		log.Fatal("cannot init leveldb:", err)
	}

	/*defer func() {
		err = ldb.Close()
		if err != nil {
			log.Fatal("cannot close leveldb:", err)
		}
	}()*/

	Db = &leveldbDatabase{db: ldb}
}

func (t *leveldbDatabase) PutSlate(slate Slate) error {
	id, err := slate.ID.MarshalText()
	if err != nil {
		return errors.Wrap(err, "cannot marshal ID into bytes")
	}

	id = append([]byte("slate"), id...)

	slateBytes, err := json.Marshal(slate)
	if err != nil {
		return errors.Wrap(err, "cannot marshal slate into json")
	}

	err = t.db.Put(id, slateBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put slate")
	}

	return nil
}

func (t *leveldbDatabase) PutTransaction(transaction Transaction) error {
	id, err := transaction.ID.MarshalText()
	if err != nil {
		return errors.Wrap(err, "cannot marshal ID into bytes")
	}

	id = append([]byte("transaction"), id...)

	transactionBytes, err := json.Marshal(transaction)
	if err != nil {
		return errors.Wrap(err, "cannot marshal transaction into json")
	}

	err = t.db.Put(id, transactionBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put transaction")
	}

	return nil
}

func (t *leveldbDatabase) PutOutput(output Output) error {
	outputBytes, err := json.Marshal(output)
	if err != nil {
		return errors.Wrap(err, "cannot marshal output into json")
	}

	hash, _ := blake2b.New256(nil)
	hash.Write(outputBytes)

	id := hash.Sum(nil)

	id = append([]byte("output"), id...)

	err = t.db.Put(id, outputBytes, nil)
	if err != nil {
		return errors.Wrap(err, "cannot Put output")
	}

	return nil
}

func (t *leveldbDatabase) GetSlate(id []byte) (slate Slate, err error) {
	id = append([]byte("slate"), id...)

	slateBytes, err := t.db.Get(id, nil)
	if err != nil {
		return Slate{}, errors.Wrap(err, "cannot Get slate")
	}

	slate = Slate{}

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return Slate{}, errors.Wrap(err, "cannot unmarshal slateBytes")
	}

	return slate, nil
}

func (t *leveldbDatabase) GetInputs(amount uint64) (outputs []Output, err error) {
	iter := t.db.NewIterator(util.BytesPrefix([]byte("output")), nil)
	for iter.Next() {
		output := Output{}
		err = json.Unmarshal(iter.Value(), &output)
		if err != nil {
			return nil, errors.Wrap(err, "cannot unmarshal output in iterator")
		}
		if output.Status == Valid {
			output.Status = Locked
			outputs = append(outputs, output)
		}
	}

	for _, output := range outputs {
		err = Db.PutOutput(output)
		if err != nil {
			return nil, errors.Wrap(err, "cannot update output")
		}
	}

	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].Value < outputs[j].Value
	})

	return outputs, nil
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

	iter := t.db.NewIterator(util.BytesPrefix([]byte("output")), nil)
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
