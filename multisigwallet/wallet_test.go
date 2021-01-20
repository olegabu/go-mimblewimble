package multisigwallet

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/olegabu/go-mimblewimble/abci"
	"github.com/pkg/errors"
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

	id := uuid.New()
	slates := make([][]byte, 0)
	for i := 0; i < partiesCount; i++ {
		slate, err := wallets[i].InitFundingTransaction(amount, asset, id)
		assert.NoError(t, err)
		slates = append(slates, slate)
	}

	partiallySignedSlates := make([][]byte, 0)
	for i := 0; i < partiesCount; i++ {
		slate, err := wallets[i].SignFundingTransaction(slates)
		assert.NoError(t, err)
		partiallySignedSlates = append(partiallySignedSlates, slate)
	}

	_, err := wallets[0].AggregateFundingTransaction(partiallySignedSlates)
	assert.NoError(t, err)

	//err = broadcast(t, transaction)
	//assert.NoError(t, err)
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

func broadcast(t *testing.T, transactionBytes []byte) (err error) {
	client, err := abci.NewClient("tcp://0.0.0.0:26657")
	if err != nil {
		return errors.Wrap(err, "cannot get new client")
	}
	defer client.Stop()

	err = client.Broadcast(transactionBytes)
	if err != nil {
		return errors.Wrap(err, "cannot client.Broadcast")
	}
	return
}
