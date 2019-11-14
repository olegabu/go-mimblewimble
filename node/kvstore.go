package node

import (
	"bytes"
	"github.com/syndtr/goleveldb/leveldb"
	abcitypes "github.com/tendermint/tendermint/abci/types"
)

type KVStoreApplication struct {
	db           *leveldb.DB
	currentBatch *leveldb.Batch
}

func NewKVStoreApplication(db *leveldb.DB) *KVStoreApplication {
	return &KVStoreApplication{
		db: db,
	}
}

var _ abcitypes.Application = (*KVStoreApplication)(nil)

func (KVStoreApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{}
}

func (KVStoreApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
	return abcitypes.ResponseSetOption{}
}

func (KVStoreApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	return abcitypes.ResponseInitChain{}
}

func (KVStoreApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	return abcitypes.ResponseEndBlock{}
}

func (app *KVStoreApplication) isValid(tx []byte) (code uint32) {
	// check format
	parts := bytes.Split(tx, []byte("="))
	if len(parts) != 2 {
		return 1
	}

	key, value := parts[0], parts[1]

	storedValue, _ := app.db.Get(key, nil)
	//if err != leveldb.ErrNotFound {
	//	panic(err)
	//}

	if bytes.Equal(storedValue, value) {
		code = 2
	}

	return code
}

func (app *KVStoreApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code := app.isValid(req.Tx)
	return abcitypes.ResponseCheckTx{Code: code, GasWanted: 1}
}

func (app *KVStoreApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	app.currentBatch = new(leveldb.Batch)
	return abcitypes.ResponseBeginBlock{}
}

func (app *KVStoreApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	code := app.isValid(req.Tx)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code}
	}

	parts := bytes.Split(req.Tx, []byte("="))
	key, value := parts[0], parts[1]

	app.currentBatch.Put(key, value)

	return abcitypes.ResponseDeliverTx{Code: 0}
}

func (app *KVStoreApplication) Commit() abcitypes.ResponseCommit {
	err := app.db.Write(app.currentBatch, nil)
	if err != nil {
		panic(err)
	}

	return abcitypes.ResponseCommit{Data: []byte{}}
}

func (app *KVStoreApplication) Query(reqQuery abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {
	resQuery.Key = reqQuery.Data

	storedValue, err := app.db.Get(reqQuery.Data, nil)
	if err != nil {
		panic(err)
	}

	if storedValue == nil {
		resQuery.Log = "does not exist"
	} else {
		resQuery.Log = "exists"
		resQuery.Value = storedValue
	}

	return
}
