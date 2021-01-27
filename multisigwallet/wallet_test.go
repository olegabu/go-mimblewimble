package multisigwallet

import (
	"encoding/json"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/stretchr/testify/assert"
)

func TestCreateAndSpendMultiparty(t *testing.T) {
	partiesCount := 1 + rand.Intn(3)
	amount := uint64(100)
	asset := "$"

	wallets := make([]*Wallet, 0)
	for i := 0; i < partiesCount; i++ {
		wallets = append(wallets, createWalletWithBalance(t, amount+uint64(rand.Intn(100)), asset))
	}

	multipartyOutputCommit := createMultipartyUtxo(t, wallets, amount, asset)
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, multipartyOutputCommit, []uint64{50, 50, 50, 50})
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, multipartyOutputCommit, []uint64{50, 50, 50, 50})
	closeWallets(wallets)
}

func TestCreateAndSpendSingle(t *testing.T) {
	partiesCount := 1
	amount := uint64(100)
	asset := "$"

	wallets := make([]*Wallet, 0)
	for i := 0; i < partiesCount; i++ {
		wallets = append(wallets, createWalletWithBalance(t, amount+uint64(rand.Intn(100)), asset))
	}

	multipartyOutputCommit := createMultipartyUtxo(t, wallets, amount, asset)
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, multipartyOutputCommit, []uint64{50})
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, multipartyOutputCommit, []uint64{50})
	closeWallets(wallets)
}

func createWalletWithBalance(t *testing.T, balance uint64, asset string) *Wallet {
	wallet := newTestWallet(t, strconv.Itoa(rand.Int()))
	_, err := wallet.Issue(balance, asset)
	assert.NoError(t, err)
	return wallet
}

func closeWallets(wallets []*Wallet) {
	for _, wallet := range wallets {
		wallet.Close()
	}
}

func createMultipartyUtxo(t *testing.T, wallets []*Wallet, partialAmount uint64, asset string) (multipartyOutputCommit string) {
	id := uuid.New()
	count := len(wallets)

	slates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		slate, err := wallets[i].InitFundingTransaction(partialAmount, asset, id)
		assert.NoError(t, err)
		slates = append(slates, slate)
	}

	partiallySignedSlates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		slate, err := wallets[i].SignMultipartyTransaction(slates)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	var transactionBytes []byte
	for i := 0; i < count; i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateMultipartyTransaction(partiallySignedSlates)
		assert.NoError(t, err)
	}

	var transaction ledger.Transaction
	err := json.Unmarshal(transactionBytes, &transaction)
	assert.NoError(t, err)
	err = ledger.ValidateTransaction(&transaction)
	assert.NoError(t, err)

	transactionID, err := transaction.ID.MarshalText()
	assert.NoError(t, err)

	for i := 0; i < count; i++ {
		err = wallets[i].Confirm(transactionID)
		assert.NoError(t, err)
	}
	return
}

func spendMultipartyUtxo(t *testing.T, wallets []*Wallet, mulipartyOutputCommit string, payouts []uint64) (multipartyOutputCommit string) {
	id := uuid.New()
	count := len(wallets)

	slates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		payout := uint64(50)
		slate, err := wallets[i].InitSpendingTransaction(mulipartyOutputCommit, payout, id)
		assert.NoError(t, err)
		slates = append(slates, slate)
	}

	partiallySignedSlates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		slate, err := wallets[i].SignMultipartyTransaction(slates)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	var transactionBytes []byte
	for i := 0; i < count; i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateMultipartyTransaction(partiallySignedSlates)
		assert.NoError(t, err)
	}

	var transaction ledger.Transaction
	err := json.Unmarshal(transactionBytes, &transaction)
	assert.NoError(t, err)
	err = ledger.ValidateTransaction(&transaction)
	assert.NoError(t, err)

	transactionID, err := transaction.ID.MarshalText()
	assert.NoError(t, err)

	for i := 0; i < count; i++ {
		err = wallets[i].Confirm(transactionID)
		assert.NoError(t, err)
	}
	return
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
