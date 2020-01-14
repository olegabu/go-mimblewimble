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
	files := []string{
		"../../go-secp256k1-zkp/tests/1g_rep.json",
		"../../go-secp256k1-zkp/tests/10_grin_repost.json",
		"../../go-secp256k1-zkp/tests/1g_grin_repost_fix_kernel.json",
		"../../go-secp256k1-zkp/tests/100mg_repost.json",
	}
	for _, file := range files {
		testFile(t, file)
	}
}

func testFile(t *testing.T, file string) {
	log.Printf("Validating tx from file %s...\n", file)
	bytes := readFile(file)
	assert.NotEmpty(t, bytes)

	var tx *Transaction
	err := json.Unmarshal(bytes, &tx)
	//	tx, err := getTx(bytes)
	assert.NoError(t, err)

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

func TestIssue(t *testing.T) {
	bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "08dbceff37f3332cf17c0a11fd31b8c304922ec65b375d57ca545468d71e35ff54",
		"proof": "ae017b039f47d84963f18593cc8d9ad1ef57be548f2b02da5578eb978473a1b4be546d9e4ff4a2a5cbdf39ab31454beccdbb45df38667a00d63a3324e2ea016a0944f0609bd2b681686b9a0ae840639877e25e844788224e4babf671a6917a1f14950a5d8eac58a63179a99ac3da456a77395717c42e3288ac4e795b4d072dcd597863aebb27ec94ad1fb223f97367a00a3b911442b9d7cbe95f08e5332b082e8af3150f939ecccf57fa6778e52bfbbe827f30dae128213e16d86e265b5fc81f6146a19033456865ad7fc77f401a512a0ced54b9aafef14af5123ee6e41727bb72724d3643c9c4cc364ff592258e9db7e29063a0da075f173a81c31523022f332f2aad9036e137e74b6dc46d59e04be4c044fc49e2a1bbe83d7ce802606c62e6e078ed2b1d2461c6d9cd6af6b64b0ac313883fb6ee4e5872e0924718f973a24c933dae1d5f7dc7228424c17ae9f1291afe4c1400e5284eae4ce52ab2f700c6ddc3a802fe86a94e7285469b24d5eeb40201d407a96cc66908bbf3f1e1179adc2ca76bdc442d3ac38d3b32cdb069f2d3f025388ec6e20ec91e57b3f4c9903a0a413483601c79c7ce0e2bd2a2a420444f153d9a9e5534e7193fab0cc4fb67980950c9d2fca3b93a471c66bb2e0367cd80d3da474d5ddc1ef2f1d96489b6acdd2a018aa9a9d2b29ac45a8154eba18b1745fb2014f2562da981db0174e57f906f793861787ff6e5ffe219dd4297a716d995c56d177d562373ad9e4e47ddf8f79db0ce34a85be0140c57f590d82fa0bb5be3acc005e60dfff2a7d67c96702ec68d2b2718187149658a5f88ad80563ed8c19d691af7dadf42524d7fc96fe2b56fd84e5702e5753c20d57e518dbd69c5093f9578f6962c517ba1875242f222eca054abe8b35c068286b20c3af2ca2eb8425944b9828ba5993923ee40c95de9c3da7e4f6523a5ba"
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
		"commit": "08dbceff37f3332cf17c0a11fd31b8c304922ec65b375d57ca545468d71e35ff54",
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
		"proof": "ae017b039f47d84963f18593cc8d9ad1ef57be548f2b02da5578eb978473a1b4be546d9e4ff4a2a5cbdf39ab31454beccdbb45df38667a00d63a3324e2ea016a0944f0609bd2b681686b9a0ae840639877e25e844788224e4babf671a6917a1f14950a5d8eac58a63179a99ac3da456a77395717c42e3288ac4e795b4d072dcd597863aebb27ec94ad1fb223f97367a00a3b911442b9d7cbe95f08e5332b082e8af3150f939ecccf57fa6778e52bfbbe827f30dae128213e16d86e265b5fc81f6146a19033456865ad7fc77f401a512a0ced54b9aafef14af5123ee6e41727bb72724d3643c9c4cc364ff592258e9db7e29063a0da075f173a81c31523022f332f2aad9036e137e74b6dc46d59e04be4c044fc49e2a1bbe83d7ce802606c62e6e078ed2b1d2461c6d9cd6af6b64b0ac313883fb6ee4e5872e0924718f973a24c933dae1d5f7dc7228424c17ae9f1291afe4c1400e5284eae4ce52ab2f700c6ddc3a802fe86a94e7285469b24d5eeb40201d407a96cc66908bbf3f1e1179adc2ca76bdc442d3ac38d3b32cdb069f2d3f025388ec6e20ec91e57b3f4c9903a0a413483601c79c7ce0e2bd2a2a420444f153d9a9e5534e7193fab0cc4fb67980950c9d2fca3b93a471c66bb2e0367cd80d3da474d5ddc1ef2f1d96489b6acdd2a018aa9a9d2b29ac45a8154eba18b1745fb2014f2562da981db0174e57f906f793861787ff6e5ffe219dd4297a716d995c56d177d562373ad9e4e47ddf8f79db0ce34a85be0140c57f590d82fa0bb5be3acc005e60dfff2a7d67c96702ec68d2b2718187149658a5f88ad80563ed8c19d691af7dadf42524d7fc96fe2b56fd84e5702e5753c20d57e518dbd69c5093f9578f6962c517ba1875242f222eca054abe8b35c068286b20c3af2ca2eb8425944b9828ba5993923ee40c95de9c3da7e4f6523a5ba"
	  },
	  "asset": "¤"
	}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.NotNil(t, ledgerIssue)
	assert.NotNil(t, err)
}
