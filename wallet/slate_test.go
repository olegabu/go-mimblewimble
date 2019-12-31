package wallet

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	change := inputValue - amount - fee

	value1 := uint64(100)
	blind1, _ := secret(context)
	output1, _ := createOutput(context, blind1[:], value1, core.CoinbaseOutput)

	value2 := inputValue - value1
	blind2, _ := secret(context)
	output2, _ := createOutput(context, blind2[:], value2, core.CoinbaseOutput)

	inputs := []Output{{
		Output: output1,
		Blind:  blind1,
		Value:  value1,
	},
		{
			Output: output2,
			Blind:  blind2,
			Value:  value2,
		}}

	slateBytes, _, senderWalletSlate, err := CreateSlate(context, amount, fee, "cash", change, inputs)
	assert.NoError(t, err)
	fmt.Printf("send %s\n", string(slateBytes))

	responseSlateBytes, _, _, err := CreateResponse(slateBytes)
	assert.NoError(t, err)
	fmt.Printf("resp %s\n", string(responseSlateBytes))

	txBytes, _, err := CreateTransaction(responseSlateBytes, senderWalletSlate)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(txBytes))

	_, err = ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
}

func ReadSlate(filename string) (slate *Slate, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	fmt.Printf("=====BEGIN OF SLATE [%s]=====\n%s\n=====END OF SLATE=====\n", filename, string(data))
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
	kex, err := calculateExcess(context, slate.Transaction, fee)
	assert.NoError(t, err)
	fmt.Printf("calculateExcess: %s\n", kex.Hex(context))

	kex0 := slate.Transaction.Body.Kernels[0].Excess
	fmt.Printf("calculateExcess: %s\n", kex0)

	assert.Equal(t, kex0, kex.Hex(context))
}

/*
func TestGrinTx(t *testing.T) {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	files, err := ioutil.ReadDir("../")
	if err != nil {
		fmt.Println("No files found")
		return
	}

	var valcnt int
	for _, f := range files {
		fn := "../" + f.Name()
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
*/
