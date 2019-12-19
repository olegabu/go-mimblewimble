package wallet

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/blockcypher/libgrin/core"
	"github.com/stretchr/testify/assert"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
)

func TestRound(t *testing.T) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.Nil(t, err)

	defer secp256k1.ContextDestroy(context)

	blind, err := secret(context)
	assert.Nil(t, err)

	inputValue := uint64(300)
	amount := uint64(200)
	fee := uint64(30)

	change := inputValue - amount - fee

	output, err := createOutput(context, blind[:], inputValue, core.CoinbaseOutput)
	assert.Nil(t, err)

	inputs := []Output{{
		Output: output,
		Blind:  blind,
		Value:  inputValue,
	}}

	slateBytes, _, senderWalletSlate, err := CreateSlate(context, amount, fee, "cash", change, inputs)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(slateBytes))

	responseSlateBytes, _, _, err := CreateResponse(slateBytes)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(responseSlateBytes))

	txBytes, _, err := CreateTransaction(responseSlateBytes, senderWalletSlate)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(txBytes))

	tx, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
	fmt.Printf("post %v\n", tx)
}

var txPrinted bool

func ReadSlate(t *testing.T, filename string) (slate *Slate) {
	data, err := ioutil.ReadFile(filename)
	assert.NoError(t, err)
	if !txPrinted {
		fmt.Printf("=====BEGIN OF SLATE [%s]=====\n%s\n=====END OF SLATE=====\n", filename, string(data))
		txPrinted = true
	}
	slate = new(Slate)
	err = json.Unmarshal(data, slate)
	assert.NoError(t, err)
	return
}

func TestExcess(t *testing.T) {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	slate := ReadSlate(t, "../100mg_finalize.json")

	fee := uint64(slate.Fee)
	kex, err := calculateExcess(context, slate.Transaction, fee)
	assert.NoError(t, err)
	fmt.Printf("calculateExcess: %s\n", kex.Hex(context))

	kex0 := slate.Transaction.Body.Kernels[0].Excess
	fmt.Printf("calculateExcess: %s\n", kex0)

	assert.Equal(t, kex0, kex.Hex(context))
}
/*
func TestGrinExcess(t *testing.T) {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	slate := ReadSlate(t, "../1g_final.json")

}*/