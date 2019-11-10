package wallet

import (
	"encoding/json"
	"fmt"
	"github.com/olegabu/go-mimblewimble/transaction"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWalletRound(t *testing.T) {
	for _, value := range []int{1, 5, 10} {
		err := Issue(uint64(value))
		assert.Nil(t, err)
	}

	slateBytes, err := Send(7)
	assert.Nil(t, err)
	fmt.Println("send " + string(slateBytes))

	responseSlateBytes, err := Receive(slateBytes)
	assert.Nil(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	txBytes, err := Finalize(responseSlateBytes)
	assert.Nil(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = Info()

	_, err = transaction.Validate(txBytes)
	assert.Nil(t, err)

	responseSlate := Slate{}
	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	assert.Nil(t, err)
	txID, err := responseSlate.ID.MarshalText()
	assert.Nil(t, err)

	err = Confirm(txID)
	assert.Nil(t, err)

	err = Info()
}

func TestInfo(t *testing.T) {
	err := Info()
	assert.Nil(t, err)
}
