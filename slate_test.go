package mw

import (
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRound(t *testing.T) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.Nil(t, err)

	defer secp256k1.ContextDestroy(context)

	blind, err := random()
	assert.Nil(t, err)

	inputValue := uint64(40)
	amount := uint64(25)

	output, blind, err := output(context, inputValue)
	assert.Nil(t, err)

	inputs := []WalletOutput{WalletOutput{
		Output: output,
		Blind:  blind,
		Value:  inputValue,
	}}

	slateBytes, id, walletOutputBytes, walletSlateBytes, err := CreateSlate(amount, inputs)
	assert.Nil(t, err)
	fmt.Println(string(id))
	fmt.Println(string(slateBytes))
	fmt.Println(string(walletOutputBytes))
	fmt.Println(string(walletSlateBytes))

	slateResponseBytes, id, walletOutputBytes, walletSlateBytes, err := CreateResponse(slateBytes)
	assert.Nil(t, err)
	fmt.Println(string(id))
	fmt.Println(string(slateResponseBytes))
	fmt.Println(string(walletOutputBytes))
	fmt.Println(string(walletSlateBytes))

	txBytes, err := CreateTransaction(slateResponseBytes, walletSlateBytes)
	assert.Nil(t, err)
	fmt.Println(string(txBytes))

	tx, err := ValidateTransaction(txBytes)
	assert.Nil(t, err)
	fmt.Println(tx)
}
