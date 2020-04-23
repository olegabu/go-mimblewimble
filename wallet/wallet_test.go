package wallet

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/olegabu/go-mimblewimble/ledger"
)

func testDbDir() string {
	var usr, _ = user.Current()
	return filepath.Join(usr.HomeDir, ".mw_test")
}

func TestWalletRound(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err := NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)
	defer w.Close()

	_, err = w.InitMasterKey("")
	assert.NoError(t, err)

	for _, value := range []uint64{1, 2, 3} {
		_, err := w.Issue(value, "cash")
		assert.NoError(t, err)
	}

	err = w.Info()
	assert.NoError(t, err)

	slateBytes, err := w.Send(4, "cash")
	assert.NoError(t, err)
	fmt.Println("send " + string(slateBytes))

	err = w.Info()
	assert.NoError(t, err)

	responseSlateBytes, err := w.Receive(slateBytes)
	assert.NoError(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	err = w.Info()
	assert.NoError(t, err)

	txBytes, err := w.Finalize(responseSlateBytes)
	assert.NoError(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Info()
	assert.NoError(t, err)

	tx, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)

	err = w.Confirm([]byte(tx.ID.String()))
	assert.NoError(t, err)

	err = w.Info()
	assert.NoError(t, err)
}

func TestInfo(t *testing.T) {
	dir := testDbDir()
	w, err := NewWallet(dir)
	assert.NoError(t, err)
	defer w.Close()
	err = w.Info()
	assert.NoError(t, err)
}
