package wallet

import (
	"encoding/json"
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

	db := NewLeveldbDatabase(dir)
	w := NewWallet(db)
	defer db.Close()

	for _, value := range []int{3, 5, 10} {
		_, err := w.Issue(uint64(value), "cash")
		assert.NoError(t, err)
	}

	slateBytes, err := w.Send(7, "cash")
	assert.NoError(t, err)
	fmt.Println("send " + string(slateBytes))

	err = w.Info()
	assert.NoError(t, err)

	responseSlateBytes, err := w.Receive(slateBytes)
	assert.NoError(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	err = w.Info()
	assert.NoError(t, err)

	// TODO: something needs to be fixed here
	txBytes, err := w.Finalize(responseSlateBytes)
	assert.NoError(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Info()
	assert.NoError(t, err)

	_, err = ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)

	responseSlate := Slate{}
	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	assert.NoError(t, err)
	txID, err := responseSlate.ID.MarshalText()
	assert.NoError(t, err)

	err = w.Confirm(txID)
	assert.NoError(t, err)

	err = w.Info()
	assert.NoError(t, err)
}

func TestInfo(t *testing.T) {
	dir := testDbDir()
	db := NewLeveldbDatabase(dir)
	w := NewWallet(db)
	defer db.Close()
	err := w.Info()
	assert.NoError(t, err)
}
