package main

import (
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/pkg/errors"
)

type shimDatabase struct {
	stub shim.ChaincodeStubInterface
}

func NewShimDatabase(stub shim.ChaincodeStubInterface) ledger.Database {
	var d ledger.Database = &shimDatabase{stub: stub}

	return d
}

func (t *shimDatabase) Close() {
	return
}

func (t *shimDatabase) InputExists(input core.Input) error {
	o, err := t.stub.GetState(t.outputKey(input.Commit))
	if err != nil || o == nil {
		return errors.Wrapf(err, "cannot GetState input %v", input)
	}

	return nil
}

func (t *shimDatabase) SpendInput(input core.Input) error {
	err := t.stub.DelState(t.outputKey(input.Commit))
	if err != nil {
		return errors.Wrapf(err, "cannot DelState input %v", input)
	}
	return nil
}

func (t *shimDatabase) PutOutput(output core.Output) error {
	outputBytes, _ := json.Marshal(output)
	err := t.stub.PutState(t.outputKey(output.Commit), outputBytes)
	if err != nil {
		return errors.Wrapf(err, "cannot PutState output %v", output)
	}
	return nil
}

func (t *shimDatabase) Begin() {
	return
}

func (t *shimDatabase) Commit() (err error) {
	return
}

func (t *shimDatabase) GetOutput(id []byte) (outputBytes []byte, err error) {
	outputBytes, err = t.stub.GetState(t.outputKey(string(id)))
	if err != nil {
		return nil, errors.Wrapf(err, "cannot GetState output")
	}
	return
}

func (t *shimDatabase) ListOutputs() (outputsBytes []byte, err error) {
	outputs := make([]core.Output, 0)

	iter, err := t.stub.GetStateByPartialCompositeKey("output", nil)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot GetStateByPartialCompositeKey")
	}
	defer iter.Close()

	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, errors.Wrapf(err, "cannot iter.Next")
		}
		output := core.Output{}
		err = json.Unmarshal(kv.Value, &output)
		outputs = append(outputs, output)
	}

	outputsBytes, err = json.Marshal(outputs)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot marshal outputs")
	}

	return
}

func (t *shimDatabase) outputKey(commit string) string {
	key, _ := t.stub.CreateCompositeKey("output", []string{commit})
	return key
}
