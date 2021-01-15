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

}

func TestFirstStep(t *testing.T) {
	wa := newTestWallet(t, "alice")
	defer wa.Close()

	var amount uint64 = 100
	asset := "$"

	_, err := wa.Issue(amount, asset)
	assert.NoError(t, err)

	slateBytes, err := wa.InitFundingTransaction(amount, asset)
	assert.NoError(t, err)

	wb := newTestWallet(t, "bob")
	defer wb.Close()

	_, err = wb.Issue(amount, asset)
	assert.NoError(t, err)

	slateBytes, err = wb.ContributeFundingTransaction(amount, asset, slateBytes)
	assert.NoError(t, err)

	wc := newTestWallet(t, "carol")
	defer wc.Close()

	_, err = wc.Issue(amount, asset)
	assert.NoError(t, err)

	slateBytes, err = wc.ContributeFundingTransaction(amount, asset, slateBytes)
	assert.NoError(t, err)

	slateBytes, err = wa.SignFundingTransaction(slateBytes)
	assert.NoError(t, err)

	slateBytes, err = wb.SignFundingTransaction(slateBytes)
	assert.NoError(t, err)

	slateBytes, err = wc.SignFundingTransaction(slateBytes)
	assert.NoError(t, err)

	slateBytes, err = wa.AggregateFundingTransaction(slateBytes)
	assert.NoError(t, err)
	println(string(slateBytes))
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
