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

func (t *shimDatabase) PutOutput(o core.Output) error {
	bytes, _ := json.Marshal(o)
	err := t.stub.PutState(t.outputKey(o.Commit), bytes)
	if err != nil {
		return errors.Wrapf(err, "cannot PutState o %v", o)
	}
	return nil
}

func (t *shimDatabase) PutKernel(o core.TxKernel) error {
	bytes, _ := json.Marshal(o)
	err := t.stub.PutState(t.kernelKey(o), bytes)
	if err != nil {
		return errors.Wrapf(err, "cannot PutState o %v", o)
	}
	return nil
}

func (t *shimDatabase) Begin() {
	return
}

func (t *shimDatabase) Commit() (err error) {
	return
}

func (t *shimDatabase) GetOutput(id []byte) (output core.Output, err error) {
	output = core.Output{}

	outputBytes, err := t.stub.GetState(t.outputKey(string(id)))
	if err != nil {
		err = errors.Wrapf(err, "cannot GetState output")
		return
	}
	err = json.Unmarshal(outputBytes, &output)

	return
}

func (t *shimDatabase) ListOutputs() (list []core.Output, err error) {
	list = make([]core.Output, 0)

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
		o := core.Output{}
		err = json.Unmarshal(kv.Value, &o)
		list = append(list, o)
	}

	return
}

func (t *shimDatabase) ListKernels() (list []core.TxKernel, err error) {
	list = make([]core.TxKernel, 0)

	iter, err := t.stub.GetStateByPartialCompositeKey("kernel", nil)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot GetStateByPartialCompositeKey")
	}
	defer iter.Close()

	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, errors.Wrapf(err, "cannot iter.Next")
		}
		o := core.TxKernel{}
		err = json.Unmarshal(kv.Value, &o)
		list = append(list, o)
	}

	return
}

func (t *shimDatabase) AddAsset(asset string, value uint64) {
	panic("implement me")
}

func (t *shimDatabase) ListAssets() (list map[string]uint64, err error) {
	panic("implement me")
}

func (t *shimDatabase) ResetAssets() error {
	panic("implement me")
}

func (t *shimDatabase) outputKey(commit string) string {
	key, _ := t.stub.CreateCompositeKey("output", []string{commit})
	return key
}

func (t *shimDatabase) kernelKey(k core.TxKernel) string {
	key, _ := t.stub.CreateCompositeKey("kernel", []string{k.Excess})
	return key
}
