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
	file := "../100mg_repost.json" // "../100mg_repost.json"
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
	assert.NoError(t, err)

	err = ValidateTransaction(tx)
	assert.NoError(t, err)
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
	file := "../100mg_repost.json"
	bytes := getTxBytes(file)
	assert.NotEmpty(t, bytes)

	tx, err := getTx(bytes)
	assert.NoError(t, err)

	txBytes, err := json.Marshal(tx)

	_, err = ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
}

func TestIssue(t *testing.T) {
	bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "0828419ca690f41a5ef9622f715a803b39dc0690d5eb8f0e4be73bbebd2abb5786",
		"proof": "74ab8b873543c05e6f7e88b27a7c7e8191a4030570875f2944089ba0e5bb04f611cb0ae55d2cc23c10234f354bb5f9563b53c8adab00f73d06e2e186503bb2890c120bf0662db341b5ac0072acbb3e059d9bace9baa304233916fe710c8476988548714fdf5224e3ab6de05c1869af40f57d533aba451d202bc0806ca9c4817a6a9a8226485cf18ecb392f68c632a3f147a9fedba00f1592501b51f18069dffc432901c09f508f6829382dbf643b556afa9f8b52e1c955a5f0dabc29e725454f06346d6dccb15a18b857370b6ac43551f19c3377059461d3074d3450edc5c713040a8ea3334bd1663f6b03a85c2c0489f7d8d7d590562149031c811a3061d9a969e1ebfbb4122d6cd2f8a23c31ff985989269947e5f58de63c7bc9746a810e7d144bfb39edfd22ad93769a04f58205e74b644d1f56dd794b19a846a2cb5fed8993b1204865385d6eee148dbab6a1df4d4bbac63d772806fc531a4987712aa0de64e401ea4e45e16c48019a7f1de7925fdbce5df4518c9339c5cdb47a02c737de9249bf6dea487f7d924148f99adad1cc8c0d9a4469c21d5032718d43afb4e6a6d82bfde5ef6ec281fdd6a72ad991e40254045c6b7117b5831fc673b4d4e4b94eed2b6be2496f7225ab7124e0ef0e5670997a1261313c313eded9ded78fd494189b738812e02942ed5a6fa674064c6a0521edfad52b884b5659ccafa71e1016116c695d70d2a87c40e935003e4e0f93179f912801b64f04abceb8e4601e54eba5ab86a59fab61251cf5eae8541c90182a801ed9a0c4da99f0a2347d95c1fd2ca4f2766ebe49868534a0d5dd578759421d7923736160c7b836872c4e3cde15d8688f545440fcf654dd7d23cef863e9d8a796caf04dcebb9c0de3e8285a6b5cdffb45a28166d4a8a8a86969dc5231ca92b76db0b9da9d185cbb4d21e0782973ed30e1e871"
	  },
	  "asset": "¤"
	}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.NotNil(t, ledgerIssue)
	assert.Nil(t, err)
}

func TestIssueInvalidBulletProof(t *testing.T) {
	bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "0828419ca690f41a5ef9622f715a803b39dc0690d5eb8f0e4be73bbebd2abb5786",
		"proof": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
	  },
	  "asset": "¤"
	}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.NotNil(t, ledgerIssue)
	assert.NotNil(t, err)
}

func TestIssueInvalidCommit(t *testing.T) {
	bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
		"proof": "74ab8b873543c05e6f7e88b27a7c7e8191a4030570875f2944089ba0e5bb04f611cb0ae55d2cc23c10234f354bb5f9563b53c8adab00f73d06e2e186503bb2890c120bf0662db341b5ac0072acbb3e059d9bace9baa304233916fe710c8476988548714fdf5224e3ab6de05c1869af40f57d533aba451d202bc0806ca9c4817a6a9a8226485cf18ecb392f68c632a3f147a9fedba00f1592501b51f18069dffc432901c09f508f6829382dbf643b556afa9f8b52e1c955a5f0dabc29e725454f06346d6dccb15a18b857370b6ac43551f19c3377059461d3074d3450edc5c713040a8ea3334bd1663f6b03a85c2c0489f7d8d7d590562149031c811a3061d9a969e1ebfbb4122d6cd2f8a23c31ff985989269947e5f58de63c7bc9746a810e7d144bfb39edfd22ad93769a04f58205e74b644d1f56dd794b19a846a2cb5fed8993b1204865385d6eee148dbab6a1df4d4bbac63d772806fc531a4987712aa0de64e401ea4e45e16c48019a7f1de7925fdbce5df4518c9339c5cdb47a02c737de9249bf6dea487f7d924148f99adad1cc8c0d9a4469c21d5032718d43afb4e6a6d82bfde5ef6ec281fdd6a72ad991e40254045c6b7117b5831fc673b4d4e4b94eed2b6be2496f7225ab7124e0ef0e5670997a1261313c313eded9ded78fd494189b738812e02942ed5a6fa674064c6a0521edfad52b884b5659ccafa71e1016116c695d70d2a87c40e935003e4e0f93179f912801b64f04abceb8e4601e54eba5ab86a59fab61251cf5eae8541c90182a801ed9a0c4da99f0a2347d95c1fd2ca4f2766ebe49868534a0d5dd578759421d7923736160c7b836872c4e3cde15d8688f545440fcf654dd7d23cef863e9d8a796caf04dcebb9c0de3e8285a6b5cdffb45a28166d4a8a8a86969dc5231ca92b76db0b9da9d185cbb4d21e0782973ed30e1e871"
	  },
	  "asset": "¤"
	}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.NotNil(t, ledgerIssue)
	assert.NotNil(t, err)
}
