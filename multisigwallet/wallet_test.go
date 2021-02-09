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

	receiver := createWalletWithBalance(t, 0, asset)
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, participantIDs, multipartyOutputCommit, 100, asset, receiver)
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, participantIDs, multipartyOutputCommit, 100, asset, receiver)
	multipartyOutputCommit = spendMultipartyUtxo(t, wallets, participantIDs, multipartyOutputCommit, 100, asset, receiver)
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
		slate, err := wallets[i].FundMultiparty(partialAmount, asset, id, participantIDs[i])
		assert.NoError(t, err)
		slates = append(slates, slate)
	}

	partiallySignedSlates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		slate, err := wallets[i].SignMultiparty(slates)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	var transactionBytes []byte
	for i := 0; i < count; i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateMultiparty(partiallySignedSlates)
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

func spendMultipartyUtxo(t *testing.T, wallets []*Wallet, participantIDs []string, mulipartyOutputCommit string, transferAmount uint64, asset string, receiver *Wallet) (multipartyOutputCommit string) {
	id := uuid.New()
	count := len(wallets)

	slates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		slate, err := wallets[i].SpendMultiparty(mulipartyOutputCommit, transferAmount, id, participantIDs[i])
		assert.NoError(t, err)
		slates = append(slates, slate)
	}

	combinedSlate, err := receiver.CombineMultiparty(slates)
	assert.NoError(t, err)

	receiverSlate, _, err := receiver.ReceiveMultiparty(combinedSlate, transferAmount, asset, id, "receiver")
	slates = append(slates, receiverSlate)

	partiallySignedSlates := [][]byte{receiverSlate}
	for i := 0; i < count; i++ {
		slate, err := wallets[i].SignMultiparty(slates)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	var transactionBytes []byte
	for i := 0; i < count; i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateMultiparty(partiallySignedSlates)
		assert.NoError(t, err)
	}

	var transaction ledger.Transaction
	err = json.Unmarshal(transactionBytes, &transaction)
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

func TestCreateAndSpendMOfNMultiparty(t *testing.T) {
	n := 5
	k := 3

	amount := uint64(100)
	asset := "$"

	wallets := make([]*Wallet, 0)
	participantIDs := make([]string, 0)
	for i := 0; i < n; i++ {
		wallets = append(wallets, createWalletWithBalance(t, amount+uint64(rand.Intn(100)), asset))
		participantIDs = append(participantIDs, strconv.Itoa(i))
	}

	multipartyOutputCommit := createMultipartyMOfNUtxo(t, wallets, participantIDs, amount, asset, n, k)
	println(multipartyOutputCommit)
	activeParticipantsIDs := participantIDs[:k]
	missingParticipantIDs := participantIDs[k:]

	receiver := createWalletWithBalance(t, 0, asset)
	multipartyOutputCommit = spendMOfNMultipartyUtxo(t, wallets, activeParticipantsIDs, missingParticipantIDs, multipartyOutputCommit, uint64(n)*amount, asset, receiver)
	closeWallets(wallets)
}

func createMultipartyMOfNUtxo(t *testing.T, wallets []*Wallet, participantIDs []string, partialAmount uint64, asset string, n int, k int) (multipartyOutputCommit string) {
	id := uuid.New()
	count := len(wallets)

	allSlates := make([][][]byte, 0)
	for i := 0; i < count; i++ {
		slates, err := wallets[i].FundMOfNMultiparty(partialAmount, asset, id, participantIDs[i], n, k)
		assert.NoError(t, err)
		allSlates = append(allSlates, slates)
	}

	partiallySignedSlates := make([][]byte, 0)
	for i := 0; i < count; i++ {
		slates := make([][]byte, 0)
		for j := 0; j < len(allSlates); j++ {
			slates = append(slates, allSlates[j][i])
		}

		slate, err := wallets[i].SignMOfNMultiparty(slates, nil)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	var transactionBytes []byte
	for i := 0; i < count; i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateMOfNMultiparty(partiallySignedSlates)
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

func spendMOfNMultipartyUtxo(t *testing.T, wallets []*Wallet, activeParticipantsIDs []string, missingParticipantsIDs []string, mulipartyOutputCommit string, transferAmount uint64, asset string, receiver *Wallet) (multipartyOutputCommit string) {
	id := uuid.New()

	slates := make([][]byte, len(activeParticipantsIDs))
	for i := 0; i < len(activeParticipantsIDs); i++ {
		slate, err := wallets[i].SpendMOfNMultiparty(mulipartyOutputCommit, transferAmount, id, activeParticipantsIDs[i], missingParticipantsIDs)
		assert.NoError(t, err)
		slates[i] = slate
	}

	missingSlates := make([][]byte, len(missingParticipantsIDs))
	for i := 0; i < len(missingParticipantsIDs); i++ {
		slate, err := wallets[0].SpendMissingParty(slates, transferAmount, missingParticipantsIDs[i])
		assert.NoError(t, err)
		missingSlates[i] = slate
	}
	slates = append(slates, missingSlates...)

	combinedSlate, err := receiver.CombineMultiparty(slates)
	assert.NoError(t, err)

	receiverSlate, _, err := receiver.ReceiveMultiparty(combinedSlate, transferAmount, asset, id, "receiver")
	slates = append(slates, receiverSlate)

	partiallySignedSlates := [][]byte{receiverSlate}
	for i := 0; i < len(activeParticipantsIDs); i++ {
		slate, err := wallets[i].SignMOfNMultiparty(slates, nil)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	for i := 0; i < len(missingParticipantsIDs); i++ {
		slate, err := wallets[0].SignMOfNMultiparty(slates, &missingParticipantsIDs[i])
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	var transactionBytes []byte
	for i := 0; i < len(activeParticipantsIDs); i++ {
		var err error
		transactionBytes, multipartyOutputCommit, err = wallets[i].AggregateMOfNMultiparty(partiallySignedSlates)
		assert.NoError(t, err)
	}

	var transaction ledger.Transaction
	err = json.Unmarshal(transactionBytes, &transaction)
	assert.NoError(t, err)
	err = ledger.ValidateTransaction(&transaction)
	assert.NoError(t, err)

	transactionID, err := transaction.ID.MarshalText()
	assert.NoError(t, err)

	for i := 0; i < len(activeParticipantsIDs); i++ {
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
