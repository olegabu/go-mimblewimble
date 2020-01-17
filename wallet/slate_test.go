package wallet

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/blockcypher/libgrin/core"
	"github.com/stretchr/testify/assert"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
)

func TestRound(t *testing.T) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.Nil(t, err)

	defer secp256k1.ContextDestroy(context)

	inputValue := uint64(300)
	amount := uint64(200)
	fee := uint64(0)
	asset := "cash"

	change := inputValue - amount - fee

	_, output1, err := createOutput(context, nil, uint64(120), core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	_, output2, err := createOutput(context, nil, inputValue-120, core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	inputs := []Output{*output1, *output2}

	slateBytes, _, senderWalletSlate, err := CreateSlate(context, amount, fee, asset, change, inputs)
	assert.NoError(t, err)
	fmt.Printf("send %s\n", string(slateBytes))

	responseSlateBytes, _, _, err := CreateResponse(slateBytes)
	assert.NoError(t, err)
	fmt.Printf("resp %s\n", string(responseSlateBytes))

	txBytes, tx, err := CreateTransaction(responseSlateBytes, senderWalletSlate)
	assert.NotNil(t, txBytes)
	assert.NotNil(t, tx)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(txBytes))

	tr, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
	assert.NotNil(t, tr)
}

func ReadSlate(filename string) (slate *Slate, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	//fmt.Printf("=====BEGIN OF SLATE [%s]=====\n%s\n=====END OF SLATE=====\n", filename, string(data))
	slate = new(Slate)
	err = json.Unmarshal(data, slate)
	return
}

func TestExcess(t *testing.T) {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	slate, err := ReadSlate("../../go-secp256k1-zkp/tests/1g_final.json")
	assert.NoError(t, err)

	fee := uint64(slate.Fee)
	kex, err := ledger.CalculateExcess(context, &slate.Transaction, fee)
	assert.NoError(t, err)
	fmt.Printf("calculateExcess: %s\n", kex.Hex(context))

	kex0 := slate.Transaction.Body.Kernels[0].Excess
	fmt.Printf("calculateExcess: %s\n", kex0)

	assert.Equal(t, kex0, kex.Hex(context))
}

func TestGrinTx(t *testing.T) {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	files, err := ioutil.ReadDir("../../go-secp256k1-zkp/tests")
	if err != nil {
		fmt.Println("No files found")
		return
	}

	var valcnt int
	for _, f := range files {
		fn := "../../go-secp256k1-zkp/tests/" + f.Name()
		if !strings.Contains(fn, ".json") {
			continue
		}
		fmt.Printf(f.Name())
		slate, err := ReadSlate(fn)
		if err != nil {
			fmt.Println(" - not a slate format file")
			continue
		}
		tx := slate.Transaction
		txBytes, err := json.Marshal(tx)
		if err == nil {
			_, err = ledger.ValidateTransactionBytes(txBytes)
			if err == nil {
				fmt.Printf(" - contains valid tx\n")
				valcnt++
			} else {
				fmt.Printf("- contains no valid tx. %v\n", err)
			}
		}
	}

	fmt.Printf("Valid %d of %d", valcnt, len(files))
	assert.True(t, valcnt > 0)
}
