package wallet

import (
	"fmt"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/transaction"
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

	slateBytes, walletOutput, walletSlate, err := CreateSlate(amount, change, inputs)
	assert.Nil(t, err)
	fmt.Println("send " + string(slateBytes))
	fmt.Println(walletOutput)
	fmt.Println(walletSlate)

	responseSlateBytes, walletOutput, walletSlate, err := CreateResponse(slateBytes)
	assert.Nil(t, err)
	fmt.Println("resp " + string(responseSlateBytes))
	fmt.Println(walletOutput)
	fmt.Println(walletSlate)

	txBytes, walletTx, err := CreateTransaction(responseSlateBytes, walletSlate)
	assert.Nil(t, err)
	fmt.Println("tx   " + string(txBytes))
	fmt.Println(walletTx)

	tx, err := transaction.Validate(txBytes)
	assert.Nil(t, err)
	fmt.Println(tx)
}
