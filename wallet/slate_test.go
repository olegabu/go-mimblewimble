package wallet

import (
	"bytes"
	"encoding/hex"
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

	blind, err := secret(context)
	assert.Nil(t, err)

	inputValue := uint64(300)
	amount := uint64(200)
	fee := uint64(10)

	change := inputValue - amount - fee

	output, err := createOutput(context, blind[:], inputValue, core.CoinbaseOutput)
	assert.Nil(t, err)

	inputs := []Output{{
		Output: output,
		Blind:  blind,
		Value:  inputValue,
	}}

	slateBytes, _, senderWalletSlate, err := CreateSlate(context, amount, fee, "cash", change, inputs)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(slateBytes))

	responseSlateBytes, _, _, err := CreateResponse(slateBytes)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(responseSlateBytes))

	txBytes, _, err := CreateTransaction(responseSlateBytes, senderWalletSlate)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(txBytes))

	tx, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
	fmt.Printf("post %v\n", tx)
}

var txPrinted bool

func ReadSlate(t *testing.T, filename string) (slate *Slate) {
	data, err := ioutil.ReadFile(filename)
	assert.NoError(t, err)
	if !txPrinted {
		fmt.Printf("=====BEGIN OF SLATE [%s]=====\n%s\n=====END OF SLATE=====\n", filename, string(data))
		txPrinted = true
	}
	slate = new(Slate)
	err = json.Unmarshal(data, slate)
	assert.NoError(t, err)
	return
}

func TestExcess(t *testing.T) {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	slate := ReadSlate(t, "1g_final.json")

	kernelExcess, err := calculateExcess(context, slate.Transaction, slate.Fee)
	assert.NoError(t, err)

	// Verify kernel sums

	commitSumOverage, err := secp256k1.CommitSum(context, inputs, outputs)
	assert.NoError(t, err)
	assert.NotNil(t, commitSumOverage)
	assert.IsType(t, secp256k1.Commitment{}, *commitSumOverage)

	fmt.Printf("commitSumOverage=0x%s\n", commitSumOverage.Hex())

	// sum_kernel_excesses
	offset_bytes, err := hex.DecodeString(tx.Offset)
	excess_bytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)

	var offset_32 [32]byte

	copy(offset_32[:], offset_bytes[:32])

	commit_offset, err := secp256k1.Commit(context, offset_32[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, commit_offset)
	assert.IsType(t, secp256k1.Commitment{}, *commit_offset)

	fmt.Printf("commit_offset=0x%s\n", commit_offset.Hex())

	commit_excess, err := secp256k1.CommitmentParse(context, excess_bytes)

	commits_offset_excess := [2]*secp256k1.Commitment{commit_offset, commit_excess}

	empty_array := make([]*secp256k1.Commitment, 0)

	commitSumOffsetExcess, err := secp256k1.CommitSum(context, empty_array, commits_offset_excess[:])

	serializeSumOffsetExcess, err := secp256k1.CommitmentSerialize(context, commitSumOffsetExcess)

	fmt.Printf("commitSumOffsetExcess=0x%s\n", commitSumOffsetExcess.Hex())
	serializeCommitSumOverage, err := secp256k1.CommitmentSerialize(context, commitSumOverage)

	//fmt.Printf("serializeCommitSumOverage=0x%s\n", hex.EncodeToString(serializeCommitSumOverage[:]))
	assert.True(t, bytes.Compare(serializeSumOffsetExcess[:], serializeCommitSumOverage[:]) == 0)

	secp256k1.ContextDestroy(context)
}

