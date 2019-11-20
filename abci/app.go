package abci

import (
	"fmt"
	_ "github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/pkg/errors"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/log"
	"net/http"
	"os"
	"strings"
)

type MWApplication struct {
	db     ledger.Database
	logger log.Logger
}

func NewMWApplication(db ledger.Database) *MWApplication {
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

func (app *MWApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	tx, err := ledger.ValidateTransaction(req.Tx)
	if err != nil {
		return abcitypes.ResponseCheckTx{Code: http.StatusUnauthorized, GasWanted: 1, Log: errors.Wrap(err, "transaction is invalid").Error()}
	}

	return abcitypes.ResponseCheckTx{Code: abcitypes.CodeTypeOK, GasWanted: 1, Log: fmt.Sprintf("transaction %v is valid", tx.ID)}
}

func (app *MWApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	app.db.Begin()
	return abcitypes.ResponseBeginBlock{}
}

func (app *MWApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	tx, err := ledger.ValidateTransaction(req.Tx)
	if err != nil {
		return abcitypes.ResponseDeliverTx{Code: http.StatusUnauthorized, Log: errors.Wrap(err, "transaction is invalid").Error()}
	}

	err = ledger.PersistTransaction(tx, app.db)
	if err != nil {
		return abcitypes.ResponseDeliverTx{Code: http.StatusInternalServerError, Log: errors.Wrap(err, "cannot persist transaction").Error()}
	}

	return abcitypes.ResponseDeliverTx{Code: abcitypes.CodeTypeOK, Events: transferEvents(*tx)}
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
			outputsBytes, err := app.db.ListOutputs()
			if err != nil {
				resQuery.Log = errors.Wrap(err, "cannot list outputs").Error()
			} else {
				resQuery.Value = outputsBytes
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
func transferEvents(tx ledger.Transaction) []abcitypes.Event {
	return []abcitypes.Event{
		{
			Type: "transfer",
			Attributes: common.KVPairs{
				{Key: []byte("id"), Value: []byte(tx.ID.String())},
			},
		},
	}
}
