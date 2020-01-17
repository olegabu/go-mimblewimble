package ledger

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"testing"

	"github.com/blockcypher/libgrin/libwallet"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	files := []string{
		"../../go-secp256k1-zkp/tests/1g_rep.json",
		"../../go-secp256k1-zkp/tests/10_grin_repost.json",
		"../../go-secp256k1-zkp/tests/200_repost.json",
	//	"../../go-secp256k1-zkp/tests/100mg_repost.json",
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
		"commit": "092e6fdf366508bcbab6a336639f8046fe8b26ea58858035ab1110199d355e85ab",
		"proof": "6de4e50fcfdaa8013313145413df2b72ba9067dd77148533f52d3bbcffd7b64d5107eb494281b86fa568c92e91a9c9b787d5ff58603ac47af84b3ef8b56c8d54063f16aa44eef14dd3225e90dfffdab80f9a669c28b97c060a545a140900ea801a18746ea5c20756129b6437719d409a24a0f2d3a7a027b231567bcb914fbee06e9ed85477b1fe6a2febec76e86b5b4873f2f8e782538f4be61e6f1683571c41176d5e63a287a14bd05ccaae727d32130d7cda80b191d86f1d173979efd67c0357dbe81dfe9595eee143d1ef82519c47ca2883fe02132ea149e402d17d070e72badf2bea4f79acda686db213911f2fba835d7ff8d3a60cd459c8c74e87a23a83f9e78b28da57553a22aa4bbe822689d8dbd10b2369c833d75cbdd1dec359e60fffbab5610019649a4f107b26fb6139be230663c87aa3fb092c86bcd832cf8131b25285f453a9f285baefd078795203667d32caf27af0922dde775e6e60f404041d49032f989cc62f5b78257b641ccdb796077c43e29761b79e60a626bbaf0ba14a8b2451a9a9dfa92494cf810e9047e0852bd911a5cb42a9a0513db69308ad58c323b6c1d33b79e0f8a1cb6a574cd58c9d0691c8825b46592fc418c2ffc5f7380f5d3a5f8698d1b5073a8d2a0b75e10e9860977b841d8877f254a9561a70b4230388bc54a648398e52a6e7b5efd5a334c0c18f71d762bf833fb6237cf2cc588ac09075e772e6c803096bfb121abc116dc48231decc07bf0599732fed20033182c78b691dd8c96f5ea2dfae225ccc916f4792a6de96f364ce42eac13fb5e9a083b38194a9aa84a16f2d2445546c7779a412d4553d8f69411f6e30a8232d2b8bc3bf1aa63e2fd1bc28b3ad2c9e8710e1fc884edd42a3b0673392c0cd6801869ccb54dd1a6cb2d0d61bfaa96876ee71f5c735879f9b0122e10f1a260f8bb0c892b129a2d5"
	  },
	  "asset": "¤"
	}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.NoError(t, err)
	assert.NotNil(t, ledgerIssue)
}

func TestIssueInvalidBulletProof(t *testing.T) {
	bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "092e6fdf366508bcbab6a336639f8046fe8b26ea58858035ab1110199d355e85ab",
		"proof": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
	  },
	  "asset": "¤"
	}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.Error(t, err)
	assert.NotNil(t, ledgerIssue)
}

func TestIssueInvalidCommit(t *testing.T) {
	bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
		"proof": "6de4e50fcfdaa8013313145413df2b72ba9067dd77148533f52d3bbcffd7b64d5107eb494281b86fa568c92e91a9c9b787d5ff58603ac47af84b3ef8b56c8d54063f16aa44eef14dd3225e90dfffdab80f9a669c28b97c060a545a140900ea801a18746ea5c20756129b6437719d409a24a0f2d3a7a027b231567bcb914fbee06e9ed85477b1fe6a2febec76e86b5b4873f2f8e782538f4be61e6f1683571c41176d5e63a287a14bd05ccaae727d32130d7cda80b191d86f1d173979efd67c0357dbe81dfe9595eee143d1ef82519c47ca2883fe02132ea149e402d17d070e72badf2bea4f79acda686db213911f2fba835d7ff8d3a60cd459c8c74e87a23a83f9e78b28da57553a22aa4bbe822689d8dbd10b2369c833d75cbdd1dec359e60fffbab5610019649a4f107b26fb6139be230663c87aa3fb092c86bcd832cf8131b25285f453a9f285baefd078795203667d32caf27af0922dde775e6e60f404041d49032f989cc62f5b78257b641ccdb796077c43e29761b79e60a626bbaf0ba14a8b2451a9a9dfa92494cf810e9047e0852bd911a5cb42a9a0513db69308ad58c323b6c1d33b79e0f8a1cb6a574cd58c9d0691c8825b46592fc418c2ffc5f7380f5d3a5f8698d1b5073a8d2a0b75e10e9860977b841d8877f254a9561a70b4230388bc54a648398e52a6e7b5efd5a334c0c18f71d762bf833fb6237cf2cc588ac09075e772e6c803096bfb121abc116dc48231decc07bf0599732fed20033182c78b691dd8c96f5ea2dfae225ccc916f4792a6de96f364ce42eac13fb5e9a083b38194a9aa84a16f2d2445546c7779a412d4553d8f69411f6e30a8232d2b8bc3bf1aa63e2fd1bc28b3ad2c9e8710e1fc884edd42a3b0673392c0cd6801869ccb54dd1a6cb2d0d61bfaa96876ee71f5c735879f9b0122e10f1a260f8bb0c892b129a2d5"
	  },
	  "asset": "¤"
	}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.Error(t, err)
	assert.NotNil(t, ledgerIssue)
}
