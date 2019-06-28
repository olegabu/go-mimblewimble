package main

import (
	"github.com/blockcypher/libgrin/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateTx(t *testing.T) {
	inputs := []core.Input{{Commit: core.JSONableSlice{}}}
	outputs := []core.Output{{Commit: core.JSONableSlice{}}, {Commit: core.JSONableSlice{}}}
	kernels := []core.TxKernel{{Excess: core.JSONableSlice{}, ExcessSig: core.JSONableSlice{}}}
	body := core.TransactionBody{Inputs: inputs, Outputs: outputs, Kernels: kernels}
	tx := core.Transaction{Body: body}
	assert.Nil(t, ValidateTx(tx))
}
