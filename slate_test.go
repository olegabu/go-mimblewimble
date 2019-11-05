package mw

import (
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateSlate(t *testing.T) {
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

	slateBytes, err := CreateSlate(amount, inputs)

	fmt.Println(string(slateBytes))
	assert.NotNil(t, slateBytes)
	assert.Nil(t, err)
}
