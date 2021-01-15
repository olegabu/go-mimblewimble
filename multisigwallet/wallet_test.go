package multisigwallet

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateMultipartyUtxo(t *testing.T) {
	partiesCount := 4
	amount := uint64(100)
	asset := "$"
	wallets := make([]*Wallet, 0)
	for i := 0; i < partiesCount; i++ {
		wallet := newTestWallet(t, strconv.Itoa(i))
		defer wallet.Close()

		_, err := wallet.Issue(amount, asset)
		assert.NoError(t, err)

		wallets = append(wallets, wallet)
	}

	slate, err := wallets[0].InitFundingTransaction(amount, asset)
	assert.NoError(t, err)

	for i := 1; i < partiesCount; i++ {
		slate, err = wallets[i].ContributeFundingTransaction(amount, asset, slate)
		assert.NoError(t, err)
	}

	for i := 0; i < partiesCount; i++ {
		slate, err = wallets[i].SignFundingTransaction(slate)
		assert.NoError(t, err)
	}

	_, err = wallets[0].AggregateFundingTransaction(slate)
	assert.NoError(t, err)
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
