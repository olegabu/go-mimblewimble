package node

import (
	"encoding/json"
	"fmt"
	"github.com/blockcypher/libgrin/core"
	_ "github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/transaction"
	"github.com/pkg/errors"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/log"
	"net/http"
	"os"
	"strings"
)

type Database interface {
	Begin()
	InputExists(input core.Input) error
	SpendInput(input core.Input) error
	PutOutput(output core.Output) error
	Commit() error
	Close()
	GetOutput(id []byte) (outputBytes []byte, err error)
	ListOutputs() (outputs []core.Output, err error)
}

type MWApplication struct {
	db     Database
	logger log.Logger
}

func NewMWApplication(db Database) *MWApplication {
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
		return http.StatusUnauthorized, tx, errors.Wrap(err, "transaction is invalid")
	}

	return abcitypes.CodeTypeOK, tx, nil
}

func (app *MWApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code, tx, err := app.isValid(req.Tx)
	var responseLog string
	if err != nil {
		responseLog = err.Error()
	} else {
		responseLog = fmt.Sprintf("transaction %v is valid", tx.ID)
	}
	return abcitypes.ResponseCheckTx{Code: code, GasWanted: 1, Log: responseLog}
}

func (app *MWApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	app.db.Begin()
	return abcitypes.ResponseBeginBlock{}
}

func (app *MWApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	code, tx, err := app.isValid(req.Tx)
	if err != nil {
		return abcitypes.ResponseDeliverTx{Code: code, Log: err.Error()}
	}

	// check if inputs exist and mark them spent
	for _, input := range tx.Body.Inputs {
		err = app.db.InputExists(input)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: http.StatusNotFound, Log: err.Error()}
		}

		err = app.db.SpendInput(input)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: http.StatusInternalServerError, Log: err.Error()}
		}
	}

	// save new outputs
	for _, output := range tx.Body.Outputs {
		err = app.db.PutOutput(output)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: http.StatusInternalServerError, Log: err.Error()}
		}
	}

	return abcitypes.ResponseDeliverTx{Code: code, Events: transferEvents(*tx)}
}

func (app *MWApplication) Commit() abcitypes.ResponseCommit {
	data := []byte{0}
	err := app.db.Commit()
	if err != nil {
		data = []byte(err.Error())
	}
	return abcitypes.ResponseCommit{Data: data}
}

func (app *MWApplication) Query(reqQuery abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {
	app.logger.Debug(fmt.Sprintf("reqQuery %v", reqQuery))

	resQuery.Key = []byte(reqQuery.Path)

	paths := strings.Split(reqQuery.Path, "/")

	if paths[0] == "output" {
		if len(paths) == 1 {
			// return all outputs
			outputs, err := app.db.ListOutputs()
			if err != nil {
				resQuery.Log = errors.Wrap(err, "cannot list outputs").Error()
			} else {
				value, err := json.Marshal(outputs)
				if err != nil {
					resQuery.Log = errors.Wrap(err, "cannot marshal outputs").Error()
				} else {
					resQuery.Value = value
				}
			}
		} else if len(paths) > 1 {
			// return one output
			outputBytes, err := app.db.GetOutput([]byte(paths[1]))
			if err != nil {
				resQuery.Log = errors.Wrap(err, "does not exist").Error()
			} else {
				resQuery.Log = "exists"
				resQuery.Value = outputBytes
			}
			resQuery.Value = outputBytes
		}
	}

	return
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
