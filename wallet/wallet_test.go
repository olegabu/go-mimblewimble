package wallet

import (
	"encoding/json"
	"fmt"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/stretchr/testify/assert"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func testDbDir() string {
	var usr, _ = user.Current()
	return filepath.Join(usr.HomeDir, ".mw_test")
}

func TestWalletRound(t *testing.T) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.Nil(t, err)

	db := NewLeveldbDatabase(dir)
	w := NewWallet(db)
	defer db.Close()

	for _, value := range []int{1, 5, 10} {
		_, err := w.Issue(uint64(value), "cash")
		assert.Nil(t, err)
	}

	slateBytes, err := w.Send(7, "cash")
	assert.Nil(t, err)
	fmt.Println("send " + string(slateBytes))

	err = w.Info()
	assert.Nil(t, err)

	responseSlateBytes, err := w.Receive(slateBytes)
	assert.Nil(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	err = w.Info()
	assert.Nil(t, err)

	txBytes, err := w.Finalize(responseSlateBytes)
	assert.Nil(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Info()
	assert.Nil(t, err)

	_, err = ledger.ValidateTransactionBytes(txBytes)
	assert.Nil(t, err)

	responseSlate := Slate{}
	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	assert.Nil(t, err)
	txID, err := responseSlate.ID.MarshalText()
	assert.Nil(t, err)

	err = w.Confirm(txID)
	assert.Nil(t, err)

	err = w.Info()
	assert.Nil(t, err)
}

func TestInfo(t *testing.T) {
	dir := testDbDir()
	db := NewLeveldbDatabase(dir)
	w := NewWallet(db)
	defer db.Close()
	err := w.Info()
	assert.Nil(t, err)
}
