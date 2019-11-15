package node

import (
	"encoding/json"
	"fmt"
	"github.com/blockcypher/libgrin/core"
	_ "github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/transaction"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/log"
	"os"
	"strings"
)

type MWApplication struct {
	db           *leveldb.DB
	currentBatch *leveldb.Batch
	logger       log.Logger
}

func NewMWApplication(db *leveldb.DB) *MWApplication {
	return &MWApplication{
		db:     db,
		logger: log.NewTMLogger(log.NewSyncWriter(os.Stdout)),
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

func (app *MWApplication) isValid(txBytes []byte) (code uint32, tx *transaction.Transaction, err error) {
	app.logger.Debug("isValid", string(txBytes))

	tx, err = transaction.Validate(txBytes)
	if err != nil {
		return 1, tx, errors.Wrapf(err, "transaction is invalid")
	}

	for _, input := range tx.Body.Inputs {
		_, err = app.db.Get(outputKey(input.Commit), nil)
		if err != nil {
			return 1, tx, errors.Wrapf(err, "cannot get input %v", input)
		}
	}

	return abcitypes.CodeTypeOK, tx, nil
}

func (app *MWApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code, tx, err := app.isValid(req.Tx)
	var log string
	if err != nil {
		log = err.Error()
	} else {
		log = fmt.Sprintf("transaction %v is valid", tx.ID)
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
		app.currentBatch.Delete(outputKey(input.Commit))
	}

	// create new outputs
	for _, output := range tx.Body.Outputs {
		outputBytes, _ := json.Marshal(output)
		app.currentBatch.Put(outputKey(output.Commit), outputBytes)
	}

	return abcitypes.ResponseDeliverTx{Code: code, Events: transferEvents(*tx)}
}

func (app *MWApplication) Commit() abcitypes.ResponseCommit {
	err := app.db.Write(app.currentBatch, nil)
	if err != nil {
		panic(err)
	}

	return abcitypes.ResponseCommit{Data: []byte{}}
}

func (app *MWApplication) Query(reqQuery abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {
	app.logger.Debug(fmt.Sprintf("reqQuery %v", reqQuery))

	resQuery.Key = []byte(reqQuery.Path)

	paths := strings.Split(reqQuery.Path, "/")

	if paths[0] == "output" {
		if len(paths) == 1 {
			// return all outputs
			outputs := make([]core.Output, 0)

			iter := app.db.NewIterator(util.BytesPrefix([]byte("output")), nil)
			for iter.Next() {
				//app.logger.Debug("iter", iter.Key(), iter.Value())
				output := core.Output{}
				_ = json.Unmarshal(iter.Value(), &output)
				outputs = append(outputs, output)
			}
			iter.Release()
			_ = iter.Error()

			resQuery.Value, _ = json.Marshal(outputs)
		} else if len(paths) > 1 {
			// return one output
			outputBytes, err := app.db.Get(outputKey(paths[1]), nil)

			if err != nil {
				resQuery.Log = "does not exist"
			} else {
				resQuery.Log = "exists"
				resQuery.Value = outputBytes
			}
			resQuery.Value = outputBytes
		}
	}

	return
}

func outputKey(commit string) []byte {
	return append([]byte("output"), []byte(commit)...)
}

// see https://github.com/tendermint/tendermint/blob/60827f75623b92eff132dc0eff5b49d2025c591e/docs/spec/abci/abci.md#events
// see https://github.com/tendermint/tendermint/blob/master/UPGRADING.md
func transferEvents(tx transaction.Transaction) []abcitypes.Event {
	return []abcitypes.Event{
		{
			Type: "transfer",
			Attributes: common.KVPairs{
				{Key: []byte("id"), Value: []byte(tx.ID.String())},
			},
		},
	}
}
