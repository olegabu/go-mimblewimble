package wallet

import (
	"encoding/json"
	"fmt"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestWalletRound(t *testing.T) {
	err := os.RemoveAll(dbFilename)
	assert.Nil(t, err)

	for _, value := range []int{1, 5, 10} {
		_, err := Issue(uint64(value), "cash")
		assert.Nil(t, err)
	}

	slateBytes, err := Send(7, "cash")
	assert.Nil(t, err)
	fmt.Println("send " + string(slateBytes))

	err = Info()
	assert.Nil(t, err)

	responseSlateBytes, err := Receive(slateBytes)
	assert.Nil(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	err = Info()
	assert.Nil(t, err)

	txBytes, err := Finalize(responseSlateBytes)
	assert.Nil(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = Info()
	assert.Nil(t, err)

	_, err = ledger.ValidateTransaction(txBytes)
	assert.Nil(t, err)

	responseSlate := Slate{}
	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	assert.Nil(t, err)
	txID, err := responseSlate.ID.MarshalText()
	assert.Nil(t, err)

	err = Confirm(txID)
	assert.Nil(t, err)

	err = Info()
	assert.Nil(t, err)
}

func TestInfo(t *testing.T) {
	err := Info()
	assert.Nil(t, err)
}
