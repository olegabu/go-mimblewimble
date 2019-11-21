package wallet

import (
	"fmt"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRound(t *testing.T) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.Nil(t, err)

	defer secp256k1.ContextDestroy(context)

	blind, err := secret()
	assert.Nil(t, err)

	inputValue := uint64(40)
	amount := uint64(40)
	change := uint64(0)

	output, blind, err := output(context, inputValue, core.CoinbaseOutput)
	assert.Nil(t, err)

	inputs := []Output{{
		Output: output,
		Blind:  blind,
		Value:  inputValue,
	}}

	slateBytes, _, senderWalletSlate, err := CreateSlate(amount, "cash", change, inputs)
	assert.Nil(t, err)
	fmt.Println("send " + string(slateBytes))

	responseSlateBytes, _, _, err := CreateResponse(slateBytes)
	assert.Nil(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	txBytes, _, err := CreateTransaction(responseSlateBytes, senderWalletSlate)
	assert.Nil(t, err)
	fmt.Println("tx   " + string(txBytes))

	tx, err := ledger.ValidateTransaction(txBytes)
	assert.Nil(t, err)
	fmt.Println(tx)
}
