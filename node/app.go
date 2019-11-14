package node

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	_ "github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/transaction"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"strings"
)

type MWApplication struct {
	db           *leveldb.DB
	currentBatch *leveldb.Batch
}

func NewMWApplication(db *leveldb.DB) *MWApplication {
	return &MWApplication{
		db: db,
	}
}

var _ abcitypes.Application = (*MWApplication)(nil)

func (MWApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{}
}

func (MWApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
	return abcitypes.ResponseSetOption{}
}

func (MWApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	return abcitypes.ResponseInitChain{}
}

func (MWApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	return abcitypes.ResponseEndBlock{}
}

func (app *MWApplication) isValid(txBytes []byte) (code uint32, tx *core.Transaction, err error) {
	tx, err = transaction.Validate(txBytes)
	if err != nil {
		return 1, tx, errors.Wrapf(err, "transaction is invalid")
	}

	for _, input := range tx.Body.Inputs {
		_, err = app.db.Get([]byte(input.Commit), nil)
		if err != nil {
			return 1, tx, errors.Wrapf(err, "cannot get input %v", input)
		}
	}

	return 0, tx, nil
}

func (app *MWApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code, _, err := app.isValid(req.Tx)
	var log string
	if err != nil {
		log = err.Error()
	} else {
		log = "transaction is valid"
	}
	return abcitypes.ResponseCheckTx{Code: code, GasWanted: 1, Log: log}
}

func (app *MWApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	app.currentBatch = new(leveldb.Batch)
	return abcitypes.ResponseBeginBlock{}
}

func (app *MWApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	code, tx, err := app.isValid(req.Tx)
	if err != nil {
		return abcitypes.ResponseDeliverTx{Code: code, Log: err.Error()}
	}

	// delete spent inputs

	for _, input := range tx.Body.Inputs {
		_, err = app.db.Get([]byte(input.Commit), nil)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: 1, Log: errors.Wrapf(err, "cannot get input %v", input).Error()}
		}
		app.currentBatch.Delete([]byte(input.Commit))
	}

	// create new outputs

	for _, output := range tx.Body.Outputs {
		app.currentBatch.Put([]byte(output.Commit), []byte(output.Commit))
	}

	return abcitypes.ResponseDeliverTx{Code: 0}
}

func (app *MWApplication) Commit() abcitypes.ResponseCommit {
	err := app.db.Write(app.currentBatch, nil)
	if err != nil {
		panic(err)
	}

	return abcitypes.ResponseCommit{Data: []byte{}}
}

func (app *MWApplication) Query(reqQuery abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {
	resQuery.Key = []byte(reqQuery.Path)

	paths := strings.Split(reqQuery.Path, "/")

	if paths[0] == "output" {
		if len(paths) == 1 {
			// return all outputs

			outputs := make([]core.Output, 0)

			iter := app.db.NewIterator(util.BytesPrefix([]byte("output")), nil)
			for iter.Next() {
				output := core.Output{}
				_ = json.Unmarshal(iter.Value(), &output)
				outputs = append(outputs, output)
			}
			iter.Release()
			_ = iter.Error()

			resQuery.Value, _ = json.Marshal(outputs)
		} else if len(paths) > 1 {
			// return one output

			keyBytes := []byte(paths[1])

			outputBytes, err := app.db.Get(keyBytes, nil)
			if err != nil {
				resQuery.Log = "does not exist"
			} else {
				resQuery.Log = "exists"
				resQuery.Value = outputBytes
			}

			resQuery.Value = []byte(paths[1])
		}
	}

	return
}
