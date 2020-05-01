package abci

import (
	"encoding/binary"
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"log"
	"path/filepath"
)

var dbFilename string

type leveldbDatabase struct {
	db           *leveldb.DB
	currentBatch *leveldb.Batch
}

func NewLeveldbDatabase(dbDir string) (d ledger.Database, err error) {
	dbFilename = filepath.Join(dbDir, "abci")

	ldb, err := leveldb.OpenFile(dbFilename, nil)
	if err != nil {
		err = errors.Wrapf(err, "cannot open leveldb at %v", dbFilename)
		return
	}
	log.Printf("opened abci db at %v\n", dbFilename)

	d = &leveldbDatabase{db: ldb}

	return
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

func (t *leveldbDatabase) PutOutput(o core.Output) error {
	bytes, _ := json.Marshal(o)
	t.currentBatch.Put(outputKey(o.Commit), bytes)
	return nil
}

func (t *leveldbDatabase) PutKernel(o core.TxKernel) error {
	bytes, _ := json.Marshal(o)
	t.currentBatch.Put(kernelKey(o.Excess), bytes)
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

func (t *leveldbDatabase) GetOutput(id []byte) (bytes []byte, err error) {
	bytes, err = t.db.Get(outputKey(string(id)), nil)
	if err != nil {
		err = errors.Wrapf(err, "cannot db.Get")
	}
	return
}

func (t *leveldbDatabase) ListOutputs() (bytes []byte, err error) {
	list := make([]core.Output, 0)

	iter := t.db.NewIterator(outputRange(), nil)
	for iter.Next() {
		//app.logger.Debug("iter", iter.Key(), iter.Value())
		o := core.Output{}
		err = json.Unmarshal(iter.Value(), &o)
		list = append(list, o)
	}
	iter.Release()
	err = iter.Error()

	bytes, err = json.Marshal(list)
	if err != nil {
		err = errors.Wrapf(err, "cannot marshal list")
	}

	return
}

func (t *leveldbDatabase) ListKernels() (bytes []byte, err error) {
	list := make([]core.TxKernel, 0)

	iter := t.db.NewIterator(kernelRange(), nil)
	for iter.Next() {
		//app.logger.Debug("iter", iter.Key(), iter.Value())
		o := core.TxKernel{}
		err = json.Unmarshal(iter.Value(), &o)
		list = append(list, o)
	}
	iter.Release()
	err = iter.Error()

	bytes, err = json.Marshal(list)
	if err != nil {
		err = errors.Wrapf(err, "cannot marshal list")
	}

	return
}

func (t *leveldbDatabase) AddAsset(asset string, value uint64) {
	var total uint64
	totalBytes := make([]byte, 8)

	currentTotalBytes, err := t.db.Get(assetKey(asset), nil)
	if err != nil {
		total = value
	} else {
		currentTotal, _ := binary.Uvarint(currentTotalBytes)
		total = currentTotal + value
	}

	binary.PutUvarint(totalBytes, total)
	t.currentBatch.Put(assetKey(asset), totalBytes)
}

func (t *leveldbDatabase) ListAssets() (bytes []byte, err error) {
	list := make(map[string]uint64)

	iter := t.db.NewIterator(assetRange(), nil)
	for iter.Next() {
		//app.logger.Debug("iter", iter.Key(), iter.Value())
		currentTotal, _ := binary.Uvarint(iter.Value())
		list[string(iter.Key())] = currentTotal
	}
	iter.Release()
	err = iter.Error()

	bytes, err = json.Marshal(list)
	if err != nil {
		err = errors.Wrapf(err, "cannot marshal list")
	}

	return
}

func outputKey(o string) []byte {
	return []byte("output." + o)
}

func outputRange() *util.Range {
	return util.BytesPrefix([]byte("output."))
}

func kernelKey(o string) []byte {
	return []byte("kernel." + o)
}

func kernelRange() *util.Range {
	return util.BytesPrefix([]byte("kernel."))
}

func assetKey(o string) []byte {
	return []byte("asset." + o)
}

func assetRange() *util.Range {
	return util.BytesPrefix([]byte("asset."))
}
