package ledger

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/blockcypher/libgrin/libwallet"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/olegabu/go-secp256k1-zkp"
)

func getTxBytes(filename string) []byte {
	bytes, err := ioutil.ReadFile(filename) //"../1g_grin_repost_fix_kernel.json") // fails TestValidateCommitmentsSum
	//bytes, err := ioutil.ReadFile("../10_grin_repost.json")
	//bytes, err := ioutil.ReadFile("../1g_final.json")

	if err != nil {
		log.Panicf("cannot open json file with test transaction: %s", filename)
	}
	fmt.Printf("Loaded file %s:\n%s\n", filename, string(bytes))

	return bytes
}

func TestValidate(t *testing.T) {
	file := "../1g_grin_repost_fix_kernel.json" // "../100mg_repost.json"
	bytes := readFile(file)
	assert.NotEmpty(t, bytes)

	var tx *Transaction
	err := json.Unmarshal(bytes, &tx)

	//	tx, err := getTx(bytes)
	assert.Nil(t, err)
	assert.NotNil(t, tx)

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.NoError(t, err)
	defer secp256k1.ContextDestroy(context)

	err = validateSignature(context, &tx.Transaction)
	//err = ValidateTransaction(tx)
	assert.Nil(t, err)
}

func readFile(filename string) []byte {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Panicf("cannot open json file with test transaction %s", filename)
	}
	return bytes
}

func getTx(slateBytes []byte) (tx *Transaction, err error) {
	var slate libwallet.Slate

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to Transaction")
	}

	ltx := Transaction{slate.Transaction, slate.ID}

	return &ltx, nil
}

func TestValidateSlate(t *testing.T) {
	file := "../100mg_finalize.json"
	tx := getTxBytes(file)
	assert.NotEmpty(t, tx)

	//tx, err := getTx(bytes)
	//assert.NotNil(t, tx)
	//assert.Nil(t, err)

	txBytes, err := json.Marshal(tx)

	txVal, err := ValidateTransactionBytes(txBytes)
	assert.NotNil(t, txVal)
	assert.Nil(t, err)
}
