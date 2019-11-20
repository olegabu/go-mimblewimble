package chaincode

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type shimDatabase struct {
	stub           shim.ChaincodeStubInterface
}

func NewShimDatabase(stub shim.ChaincodeStubInterface) ledger.Database {
	var d ledger.Database = &shimDatabase{stub: stub}

	return d
}

func (t *shimDatabase) Close() {
	return
}

func (t *shimDatabase) InputExists(input core.Input) error {
	_, err := t.stub.GetState(outputKey(input.Commit), nil)
	if err != nil {
		return errors.Wrapf(err, "cannot get input %v", input)
	}

	return nil
}

func (t *shimDatabase) SpendInput(input core.Input) error {
	t.currentBatch.Delete(outputKey(input.Commit))
	return nil
}

func (t *shimDatabase) PutOutput(output core.Output) error {
	outputBytes, _ := json.Marshal(output)
	t.currentBatch.Put(outputKey(output.Commit), outputBytes)
	return nil
}

func (t *shimDatabase) Begin() {
	return
}

func (t *shimDatabase) Commit() (err error) {
	return
}

func (t *shimDatabase) GetOutput(id []byte) (outputBytes []byte, err error) {
	outputBytes, err = t.stub.Get(outputKey(string(id)), nil)
	if err != nil {
		err = errors.Wrapf(err, "cannot db.Get")
	}
	return
}

func (t *shimDatabase) ListOutputs() (outputs []core.Output, err error) {
	outputs = make([]core.Output, 0)

	iter := t.stub.NewIterator(util.BytesPrefix([]byte("output")), nil)
	for iter.Next() {
		//app.logger.Debug("iter", iter.Key(), iter.Value())
		output := core.Output{}
		err = json.Unmarshal(iter.Value(), &output)
		outputs = append(outputs, output)
	}
	iter.Release()
	err = iter.Error()

	return
}

func outputKey(commit string) []byte {
	return append([]byte("output"), []byte(commit)...)
}
