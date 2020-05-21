package abci

import (
	"encoding/json"
	"fmt"
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
	db          ledger.Database
	logger      log.Logger
	doublespend bool
}

func NewMWApplication(db ledger.Database, doublespend bool) *MWApplication {
	return &MWApplication{
		db:          db,
		logger:      log.NewTMLogger(log.NewSyncWriter(os.Stdout)),
		doublespend: doublespend,
	}
}

var _ abcitypes.Application = (*MWApplication)(nil)

func (MWApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{}
}

func (MWApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
	return abcitypes.ResponseSetOption{}
}

func (app *MWApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	err := app.db.ResetAssets()
	if err != nil {
		app.logger.Error(fmt.Sprintf("cannot ResetAssets while in InitChain %v", err))
	}
	return abcitypes.ResponseInitChain{}
}

func (MWApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	return abcitypes.ResponseEndBlock{}
}

func (app *MWApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	tx, issue, err := ledger.Parse(req.Tx)
	if err != nil || (issue == nil && tx == nil) {
		return abcitypes.ResponseCheckTx{Code: http.StatusBadRequest, GasWanted: 1, Log: errors.Wrap(err, "cannot parse payload").Error()}
	}

	if tx != nil {
		err := ledger.ValidateTransaction(tx)
		if err != nil {
			return abcitypes.ResponseCheckTx{Code: http.StatusUnauthorized, GasWanted: 1, Log: errors.Wrap(err, "transaction is invalid").Error()}
		}
	} else {
		err := ledger.ValidateIssue(issue)
		if err != nil {
			return abcitypes.ResponseCheckTx{Code: http.StatusUnauthorized, GasWanted: 1, Log: errors.Wrap(err, "issue is invalid").Error()}
		}
	}

	return abcitypes.ResponseCheckTx{Code: abcitypes.CodeTypeOK, GasWanted: 1, Log: "valid"}
}

func (app *MWApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	app.db.Begin()
	return abcitypes.ResponseBeginBlock{}
}

func (app *MWApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	tx, issue, err := ledger.Parse(req.Tx)
	if err != nil || (issue == nil && tx == nil) {
		return abcitypes.ResponseDeliverTx{Code: http.StatusBadRequest, GasWanted: 1, Log: errors.Wrap(err, "cannot parse payload").Error()}
	}

	var events []abcitypes.Event

	if tx != nil {
		err := ledger.ValidateTransaction(tx)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: http.StatusUnauthorized, GasWanted: 1, Log: errors.Wrap(err, "transaction is invalid").Error()}
		}

		err = ledger.PersistTransaction(tx, app.db, app.doublespend)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: http.StatusInternalServerError, Log: errors.Wrap(err, "cannot persist transaction").Error()}
		}

		events = transferEvents(*tx)
	} else {
		err := ledger.ValidateIssue(issue)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: http.StatusUnauthorized, GasWanted: 1, Log: errors.Wrap(err, "issue is invalid").Error()}
		}

		err = ledger.PersistIssue(issue, app.db)
		if err != nil {
			return abcitypes.ResponseDeliverTx{Code: http.StatusInternalServerError, Log: errors.Wrap(err, "cannot persist issue").Error()}
		}

		events = issueEvents(*issue)
	}

	return abcitypes.ResponseDeliverTx{Code: abcitypes.CodeTypeOK, Events: events}
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
			list, err := app.db.ListOutputs()
			valueResponse(&resQuery, list, err)
		} else if len(paths) > 1 {
			// return one output
			bytes, err := app.db.GetOutput([]byte(paths[1]))
			valueResponse(&resQuery, bytes, err)
		}
	} else if paths[0] == "kernel" {
		list, err := app.db.ListKernels()
		valueResponse(&resQuery, list, err)
	} else if paths[0] == "asset" {
		list, err := app.db.ListAssets()
		valueResponse(&resQuery, list, err)
	} else if paths[0] == "validate" {
		outputs, err := app.db.ListOutputs()
		errorResponse(&resQuery, err, "cannot list outputs")
		kernels, err := app.db.ListKernels()
		errorResponse(&resQuery, err, "cannot list kernels")
		assets, err := app.db.ListAssets()
		errorResponse(&resQuery, err, "cannot list assets")

		msg, err := ledger.ValidateState(outputs, kernels, assets)
		logResponse(&resQuery, msg, err)
	}

	return
}

func errorResponse(resQuery *abcitypes.ResponseQuery, err error, msg string) {
	if resQuery == nil {
		return
	}
	if err != nil {
		resQuery.Log = errors.Wrap(err, msg).Error()
		resQuery.Code = http.StatusInternalServerError
	}
}

func valueResponse(resQuery *abcitypes.ResponseQuery, list interface{}, err error) {
	if resQuery == nil {
		return
	}
	if err != nil {
		errorResponse(resQuery, err, "error")
	} else {
		bytes, err := json.Marshal(list)
		errorResponse(resQuery, err, "cannot marshal")
		resQuery.Value = bytes
		resQuery.Code = http.StatusOK
	}
}

func logResponse(resQuery *abcitypes.ResponseQuery, msg string, err error) {
	if resQuery == nil {
		return
	}
	if err != nil {
		errorResponse(resQuery, err, "error")
	} else {
		resQuery.Log = msg
		resQuery.Code = http.StatusOK
	}
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

func issueEvents(issue ledger.Issue) []abcitypes.Event {
	return []abcitypes.Event{
		{
			Type: "issue",
			Attributes: common.KVPairs{
				{Key: []byte("asset"), Value: []byte(issue.Asset)},
			},
		},
	}
}
