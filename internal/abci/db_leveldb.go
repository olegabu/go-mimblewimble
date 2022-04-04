package abci

import (
	"encoding/binary"
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/pkg/ledger"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"log"
	"path/filepath"
	"strings"
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

func (t *leveldbDatabase) GetOutput(id []byte) (output core.Output, err error) {
	output = core.Output{}

	outputBytes, err := t.db.Get(outputKey(string(id)), nil)
	if err != nil {
		err = errors.Wrapf(err, "cannot db.Get")
		return
	}

	err = json.Unmarshal(outputBytes, &output)

	return
}

func (t *leveldbDatabase) ListOutputs() (list []core.Output, err error) {
	list = make([]core.Output, 0)

	iter := t.db.NewIterator(outputRange(), nil)
	for iter.Next() {
		o := core.Output{}
		err = json.Unmarshal(iter.Value(), &o)
		list = append(list, o)
	}
	iter.Release()
	err = iter.Error()

	return
}

func (t *leveldbDatabase) ListKernels() (list []core.TxKernel, err error) {
	list = make([]core.TxKernel, 0)

	iter := t.db.NewIterator(kernelRange(), nil)
	for iter.Next() {
		o := core.TxKernel{}
		err = json.Unmarshal(iter.Value(), &o)
		list = append(list, o)
	}
	iter.Release()
	err = iter.Error()

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

func (t *leveldbDatabase) ListAssets() (list map[string]uint64, err error) {
	list = make(map[string]uint64)

	iter := t.db.NewIterator(assetRange(), nil)
	for iter.Next() {
		currentTotal, _ := binary.Uvarint(iter.Value())
		list[assetFromKey(iter.Key())] = currentTotal
	}
	iter.Release()
	err = iter.Error()

	return
}

func (t *leveldbDatabase) ResetAssets() error {
	iter := t.db.NewIterator(assetRange(), nil)
	for iter.Next() {
		err := t.db.Delete(iter.Key(), nil)
		if err != nil {
			return errors.Wrap(err, "cannot delete asset")
		}
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return errors.Wrap(err, "cannot iterate over assets")
	}

	return nil
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

func assetFromKey(key []byte) string {
	s := string(key)
	return strings.Split(s, "asset.")[1]
}

func assetRange() *util.Range {
	return util.BytesPrefix([]byte("asset."))
}
