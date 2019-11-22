package abci

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/mitchellh/go-homedir"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"log"
	"os"
	"path/filepath"
)

var dbFilename string

type leveldbDatabase struct {
	db           *leveldb.DB
	currentBatch *leveldb.Batch
}

func NewLeveldbDatabase() ledger.Database {
	mwroot := os.Getenv("MWROOT")

	if mwroot == "" {
		dir, err := homedir.Dir()
		if err != nil {
			panic("cannot get homedir")
		}
		mwroot = filepath.Join(dir, ".mw")
	}

	dbFilename = filepath.Join(mwroot, "abci")

	ldb, err := leveldb.OpenFile(dbFilename, nil)
	if err != nil {
		log.Fatalf("cannot open leveldb at %v: %v", dbFilename, err)
	}
	log.Printf("opened abci db at %v\n", dbFilename)

	var d ledger.Database = &leveldbDatabase{db: ldb}

	return d
}

func (t *leveldbDatabase) Close() {
	err := t.db.Close()
	if err != nil {
		log.Fatal("cannot close leveldb:", err)
	}
}

func (t *leveldbDatabase) InputExists(input core.Input) error {
	_, err := t.db.Get(outputKey(input.Commit), nil)
	if err != nil {
		return errors.Wrapf(err, "cannot get input %v", input)
	}

	return nil
}

func (t *leveldbDatabase) SpendInput(input core.Input) error {
	t.currentBatch.Delete(outputKey(input.Commit))
	return nil
}

func (t *leveldbDatabase) PutOutput(output core.Output) error {
	outputBytes, _ := json.Marshal(output)
	t.currentBatch.Put(outputKey(output.Commit), outputBytes)
	return nil
}

func (t *leveldbDatabase) Begin() {
	t.currentBatch = new(leveldb.Batch)
}

func (t *leveldbDatabase) Commit() (err error) {
	err = t.db.Write(t.currentBatch, nil)
	if err != nil {
		err = errors.Wrapf(err, "cannot db.Write")
	}
	return
}

func (t *leveldbDatabase) GetOutput(id []byte) (outputBytes []byte, err error) {
	outputBytes, err = t.db.Get(outputKey(string(id)), nil)
	if err != nil {
		err = errors.Wrapf(err, "cannot db.Get")
	}
	return
}

func (t *leveldbDatabase) ListOutputs() (outputsBytes []byte, err error) {
	outputs := make([]core.Output, 0)

	iter := t.db.NewIterator(outputRange(), nil)
	for iter.Next() {
		//app.logger.Debug("iter", iter.Key(), iter.Value())
		output := core.Output{}
		err = json.Unmarshal(iter.Value(), &output)
		outputs = append(outputs, output)
	}
	iter.Release()
	err = iter.Error()

	outputsBytes, err = json.Marshal(outputs)
	if err != nil {
		err = errors.Wrapf(err, "cannot marshal outputs")
	}

	return
}

func outputKey(commit string) []byte {
	return []byte("output." + commit)
}

func outputRange() *util.Range {
	return util.BytesPrefix([]byte("output."))
}
