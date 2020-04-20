package wallet

import (
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestCreateAndGetMasterKey(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w := NewWallet(dir)
	defer w.Close()

	masterKey, err := w.createMasterKey()
	assert.NoError(t, err)
	assert.NotNil(t, masterKey)

	fmt.Printf("created masterKey\t%s\n", masterKey.String())

	masterKey, err = w.getMasterKey()
	assert.NoError(t, err)
	assert.NotNil(t, masterKey)

	fmt.Printf("got masterKey\t\t%s\n", masterKey.String())
}

func TestSecretFromHDWallet(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w := NewWallet(dir)
	defer w.Close()

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.NoError(t, err)

	secrets := map[uint32][32]byte{}

	for i := 0; i < 3; i++ {
		secret, index, err := w.newSecretFromHDWallet(context)
		assert.NoError(t, err)
		fmt.Printf("created i %d index %d secret %v\n", i, index, secret)
		secrets[index] = secret
	}

	fmt.Printf("created secrets %v\n", secrets)

	for i := uint32(0); i < 3; i++ {
		secret, err := w.secretFromHDWallet(context, i)
		assert.NoError(t, err)
		fmt.Printf("got i %d secret %v\n", i, secret)

		assert.EqualValues(t, secret, secrets[i])
	}
}

func TestNonce(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w := NewWallet(dir)
	defer w.Close()

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.NoError(t, err)

	nonceBytes, err := w.nonce(context)
	assert.NoError(t, err)
	assert.NotEmpty(t, nonceBytes)

	fmt.Printf("nonce %v\n", nonceBytes)
}
