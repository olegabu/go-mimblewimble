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

func TestVSS(t *testing.T) {
	n := 10
	k := randRange(1, n-1)
	wallets := make([]*Wallet, 0)

	participantIDs := make([]string, 0)
	for i := 0; i < n; i++ {
		wallets = append(wallets, createWalletWithBalance(t, 0, "$"))
		participantIDs = append(participantIDs, strconv.Itoa(i))
	}

	for i := 0; i < n; i++ {
		blindIndexes, shares, err := wallets[i].generateAndShareBlinds(participantIDs, 2, 5)
		assert.NoError(t, err)

		for i, share := range shares {
			ok, err := wallets[i].verifyShares(share)
			assert.NoError(t, err)
			assert.True(t, ok)
		}

		for j, blindIndex := range blindIndexes {
			blind, err := wallets[i].secret(blindIndex)
			assert.NoError(t, err)

			verifiableShares := make([]string, 0)
			for i := 0; i < n; i++ {
				verifiableShares = append(verifiableShares, shares[i].VerifiableShares[j].VerifiableShare)
			}
			shuffle(verifiableShares)

			openedBlind, err := wallets[i].openBlind(verifiableShares[:k])
			assert.NoError(t, err)
			assert.Equal(t, blind[:], openedBlind)
		}
	}
}

func TestCreateAndSpendMultiparty(t *testing.T) {
	partiesCount := 3
	amount := uint64(100)
	asset := "$"

	wallets := make([]*Wallet, 0)
	participantIDs := make([]string, 0)
	for i := 0; i < partiesCount; i++ {
		wallets = append(wallets, createWalletWithBalance(t, amount+uint64(rand.Intn(100)), asset))
		participantIDs = append(participantIDs, strconv.Itoa(i))
	}

	multipartyOutputCommit := createMultipartyUtxo(t, wallets, participantIDs, amount, asset)
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, participantIDs, multipartyOutputCommit, []uint64{50, 50, 50})
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, participantIDs, multipartyOutputCommit, []uint64{50, 50, 50})
	closeWallets(wallets)
}

func TestCreateAndSpendSingle(t *testing.T) {
	partiesCount := 1
	amount := uint64(100)
	asset := "$"

	wallets := make([]*Wallet, 0)
	participantIDs := make([]string, 0)
	for i := 0; i < partiesCount; i++ {
		wallets = append(wallets, createWalletWithBalance(t, amount+uint64(rand.Intn(100)), asset))
		participantIDs = append(participantIDs, strconv.Itoa(i))
	}

	multipartyOutputCommit := createMultipartyUtxo(t, wallets, participantIDs, amount, asset)
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, participantIDs, multipartyOutputCommit, []uint64{50})
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, participantIDs, multipartyOutputCommit, []uint64{50})
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

func createMultipartyUtxo(t *testing.T, wallets []*Wallet, participantIDs []string, partialAmount uint64, asset string) (multipartyOutputCommit string) {
	id := uuid.New()
	count := len(wallets)

	slates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		slate, err := wallets[i].InitFundingTransaction(partialAmount, asset, id, participantIDs[i])
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

func spendMultipartyUtxo(t *testing.T, wallets []*Wallet, participantIDs []string, mulipartyOutputCommit string, payouts []uint64) (multipartyOutputCommit string) {
	id := uuid.New()
	count := len(wallets)

	slates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		payout := uint64(50)
		slate, err := wallets[i].InitSpendingTransaction(mulipartyOutputCommit, payout, id, participantIDs[i])
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

func testDbDir(walletName string) string {
	var usr, _ = user.Current()
	return filepath.Join(usr.HomeDir, ".mw_test_"+walletName)
}

func newTestWallet(t *testing.T, walletName string) (w *Wallet) {
	dir := testDbDir(walletName)

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err = NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)

	_, err = w.InitMasterKey("")
	assert.NoError(t, err)

	return
}

func shuffle(shares []string) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}

func randRange(lower, upper int) int {
	return rand.Intn(upper+1-lower) + lower
}
