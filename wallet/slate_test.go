package wallet

import (
	"fmt"
	"testing"

	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/stretchr/testify/assert"
)

func TestRound(t *testing.T) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.Nil(t, err)

	defer secp256k1.ContextDestroy(context)

	blind, err := secret(context)
	assert.Nil(t, err)

	inputValue := uint64(300)
	amount := uint64(200)
	fee := uint64(10)

	change := inputValue - amount - fee

	output, err := createOutput(context, blind[:], inputValue, core.CoinbaseOutput)
	assert.Nil(t, err)

	inputs := []Output{{
		Output: output,
		Blind:  blind,
		Value:  inputValue,
	}}

	slateBytes, _, senderWalletSlate, err := CreateSlate(context, amount, fee, "cash", change, inputs)
	assert.Nil(t, err)
	fmt.Println("send " + string(slateBytes))

	responseSlateBytes, _, _, err := CreateResponse(slateBytes)
	assert.Nil(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	txBytes, _, err := CreateTransaction(responseSlateBytes, senderWalletSlate)
	assert.Nil(t, err)
	fmt.Println("tx   " + string(txBytes))

	tx, err := ledger.ValidateTransactionBytes(txBytes)
	assert.Nil(t, err)
	fmt.Println(tx)
}
