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

	slateBytes, senderBlind, senderNonce, err := CreateSlate(amount, inputs)
	assert.Nil(t, err)
	fmt.Println(string(slateBytes))

	slateResponseBytes, err := CreateResponse(slateBytes)
	assert.Nil(t, err)
	fmt.Println(string(slateResponseBytes))

	txBytes, err := CreateTransaction(slateResponseBytes, senderBlind, senderNonce)
	assert.Nil(t, err)
	fmt.Println(string(txBytes))
}
