package ledger

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"testing"

	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func getTxBytes() []byte {
	bytes, err := ioutil.ReadFile("../1g_grin_repost_fix_kernel.json") // fails TestValidateCommitmentsSum
	//bytes, err := ioutil.ReadFile("../10_grin_repost.json")
	//bytes, err := ioutil.ReadFile("../1g_final.json")

	if err != nil {
		log.Panic("cannot open json file with test transaction")
	}

	return bytes
}

func TestValidate(t *testing.T) {
	tx, err := ValidateTransactionBytes(getTxBytes())
	assert.NotNil(t, tx)
	assert.Nil(t, err)
}

func readFile(filename string) []byte {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Panicf("cannot open json file with test transaction %s", filename)
	}
	return bytes
}
func getTx(slateBytes []byte) (tx *core.Transaction, err error) {
	var slate libwallet.Slate

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to Transaction")
	}

	return &slate.Transaction, nil
}

func TestValidateSlate(t *testing.T) {
	bytes := readFile("../1g_final.json")

	tx, err := getTx(bytes)
	assert.NotNil(t, tx)
	assert.Nil(t, err)

	txBytes, err := json.Marshal(tx)

	txVal, err := ValidateTransactionBytes(txBytes)
	assert.NotNil(t, txVal)
	assert.Nil(t, err)
}
