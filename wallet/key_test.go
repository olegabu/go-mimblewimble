package wallet

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const testMnemonic = "dish salon sea unlock asthma rigid grass gather action dignity quiz vacuum"
const testMasterKey = "xprv9s21ZrQH143K24mEfYXCoeYDgPT5y18UJvNUc9JZZU37fRsS9znJF78KS2epJAzEbz6aRNH4fb2ptkf1AzDuBxivRx6LH9VQymyVRvw94hv"

func TestInitMasterKeyWhenDoesntExist(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)
	defer w.Close()

	createdMnemonic, err := w.InitMasterKey("")
	assert.NoError(t, err)
	assert.NotNil(t, w.masterKey)
	assert.NotEmpty(t, createdMnemonic)

	fmt.Printf("createdMnemonic %v\n", createdMnemonic)
}

func TestInitMasterKeyWhenExists(t *testing.T) {
	TestInitMasterKeyWhenDoesntExist(t)

	dir := testDbDir()

	w, err := NewWallet(dir)
	assert.NoError(t, err)
	defer w.Close()

	createdMnemonic, err := w.InitMasterKey("")
	assert.NoError(t, err)
	assert.NotNil(t, w.masterKey)
	assert.Empty(t, createdMnemonic)
}

func TestInitMasterKeyWithMnemonicWhenExists(t *testing.T) {
	TestInitMasterKeyWhenDoesntExist(t)

	dir := testDbDir()

	w, err := NewWallet(dir)
	assert.NoError(t, err)
	defer w.Close()

	_, err = w.InitMasterKey(testMnemonic)
	assert.Error(t, err)

	fmt.Printf("err %v\n", err)
}

func TestInitMasterKeyWithMnemonicWhenDoesntExist(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)
	defer w.Close()

	createdMnemonic, err := w.InitMasterKey(testMnemonic)
	assert.NoError(t, err)
	assert.NotNil(t, w.masterKey)
	assert.Empty(t, createdMnemonic)

	assert.Equal(t, testMasterKey, w.masterKey.String())
}

func TestMasterKeyFromMnemonic(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)
	defer w.Close()

	err = w.masterKeyFromMnemonic(testMnemonic)
	assert.NoError(t, err)
	assert.NotNil(t, w.masterKey)

	assert.Equal(t, testMasterKey, w.masterKey.String())
}

func TestCreateAndGetMasterKey(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)
	defer w.Close()

	mnemonic, err := w.newMasterKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, mnemonic)
	assert.NotNil(t, w.masterKey)

	fmt.Printf("created masterKey\t%s\n", w.masterKey.String())

	masterKey, err := w.masterKeyFromFile()
	assert.NoError(t, err)
	assert.NotNil(t, masterKey)

	fmt.Printf("got masterKey\t\t%s\n", masterKey.String())
}

func TestSecretFromHDWallet(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)
	defer w.Close()

	_, err = w.InitMasterKey("")
	assert.NoError(t, err)

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

	w, err := NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)
	defer w.Close()

	nonceBytes, err := w.nonce()
	assert.NoError(t, err)
	assert.NotEmpty(t, nonceBytes)

	fmt.Printf("nonce %v\n", nonceBytes)
}
