package wallet

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestCreateAndGetMasterKey(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWallet(dir)
	assert.NoError(t, err)
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

	w, err := NewWallet(dir)
	assert.NoError(t, err)
	defer w.Close()

	secrets := map[uint32][32]byte{}

	for i := 0; i < 3; i++ {
		secret, index, err := w.newSecret()
		assert.NoError(t, err)
		fmt.Printf("created i %d index %d secret %v\n", i, index, secret)
		secrets[index] = secret
	}

	fmt.Printf("created secrets %v\n", secrets)

	for i := uint32(0); i < 3; i++ {
		secret, err := w.secret(i)
		assert.NoError(t, err)
		fmt.Printf("got i %d secret %v\n", i, secret)

		assert.EqualValues(t, secret, secrets[i])
	}
}

func TestNonce(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWallet(dir)
	assert.NoError(t, err)
	defer w.Close()

	nonceBytes, err := w.nonce()
	assert.NoError(t, err)
	assert.NotEmpty(t, nonceBytes)

	fmt.Printf("nonce %v\n", nonceBytes)
}
