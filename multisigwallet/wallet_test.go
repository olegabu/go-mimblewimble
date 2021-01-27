package multisigwallet

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/stretchr/testify/assert"
)

func TestCreateAndSpendMultipartyUtxo(t *testing.T) {
	partiesCount := 4
	amount := uint64(100)
	asset := "$"
	wallets := make([]*Wallet, 0)
	for i := 0; i < partiesCount; i++ {
		wallet := newTestWallet(t, strconv.Itoa(i))
		defer wallet.Close()

		_, err := wallet.Issue(amount+5, asset)
		assert.NoError(t, err)

		wallets = append(wallets, wallet)
	}

	id := uuid.New()
	slates := make([][]byte, 0)
	for i := 0; i < partiesCount; i++ {
		slate, err := wallets[i].InitFundingTransaction(amount, asset, id)
		assert.NoError(t, err)
		slates = append(slates, slate)
	}

	partiallySignedSlates := make([][]byte, 0)
	for i := 0; i < partiesCount; i++ {
		slate, err := wallets[i].SignTransaction(slates)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	var transactionBytes []byte
	var multipartyOutputCommit string
	for i := 0; i < partiesCount; i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateTransaction(partiallySignedSlates)
		assert.NoError(t, err)
	}

	var transaction ledger.Transaction
	err := json.Unmarshal(transactionBytes, &transaction)
	assert.NoError(t, err)
	err = ledger.ValidateTransaction(&transaction)
	assert.NoError(t, err)

	transactionID, err := transaction.ID.MarshalText()
	assert.NoError(t, err)

	for i := 0; i < partiesCount; i++ {
		err = wallets[i].Confirm(transactionID)
		assert.NoError(t, err)
	}

	id = uuid.New()
	slates = make([][]byte, 0)
	for i := 0; i < partiesCount; i++ {
		payout := uint64(50)
		slate, err := wallets[i].InitSpendingTransaction(multipartyOutputCommit, payout, id)
		assert.NoError(t, err)
		slates = append(slates, slate)
	}

	partiallySignedSlates = make([][]byte, 0)
	for i := 0; i < partiesCount; i++ {
		slate, err := wallets[i].SignTransaction(slates)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	for i := 0; i < partiesCount; i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateTransaction(partiallySignedSlates)
		assert.NoError(t, err)
	}

	err = json.Unmarshal(transactionBytes, &transaction)
	assert.NoError(t, err)
	err = ledger.ValidateTransaction(&transaction)
	assert.NoError(t, err)

	transactionID, err = transaction.ID.MarshalText()
	assert.NoError(t, err)

	for i := 0; i < partiesCount; i++ {
		err = wallets[i].Confirm(transactionID)
		assert.NoError(t, err)
		wallets[i].Print()
	}
}

func testDbDir(userName string) string {
	var usr, _ = user.Current()
	return filepath.Join(usr.HomeDir, ".mw_test_"+userName)
}

func newTestWallet(t *testing.T, userName string) (w *Wallet) {
	dir := testDbDir(userName)

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err = NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)

	_, err = w.InitMasterKey("")
	assert.NoError(t, err)

	return
}
