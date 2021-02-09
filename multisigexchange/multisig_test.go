package multisigexchange

import (
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/multisigwallet"
	"github.com/stretchr/testify/assert"
)

func TestCreateMultisigUTXO(t *testing.T) {
	tendermintAddress := "tcp://0.0.0.0:26657"
	partiesCount := 3
	amount := uint64(100)
	asset := "$"

	wallets := make([]*multisigwallet.Wallet, 0)
	participantIDs := make([]string, 0)
	addresses := make([]string, 0)
	for i := 0; i < partiesCount; i++ {
		wallets = append(wallets, createWalletWithBalance(t, amount+uint64(rand.Intn(100)), asset, tendermintAddress))
		participantIDs = append(participantIDs, strconv.Itoa(i))
		address := "127.0.0.1:" + strconv.Itoa(9000+i)
		addresses = append(addresses, address)
	}

	id := uuid.New()
	var wg sync.WaitGroup
	wg.Add(partiesCount)
	for i := 0; i < partiesCount; i++ {
		participantsAddresses := make([]string, partiesCount)
		copy(participantsAddresses, addresses)
		participantsAddresses = append(participantsAddresses[:i], participantsAddresses[i+1:]...)
		go createMultipartyUtxo(wallets[i], addresses[i], amount, asset, id, participantsAddresses, tendermintAddress, i == 0, &wg)
	}
	wg.Wait()
}

func createMultipartyUtxo(
	w *multisigwallet.Wallet,
	address string,
	amount uint64,
	asset string,
	id uuid.UUID,
	participantsAddresses []string,
	tendermintAddress string,
	needBroadcast bool,
	wg *sync.WaitGroup,
) (
	multipartyUtxoCommit string,
	err error,
) {
	multipartyUtxoCommit, err = CreateMultipartyUTXO(w, address, amount, asset, id, participantsAddresses, tendermintAddress, needBroadcast)
	wg.Done()
	return
}

func createWalletWithBalance(t *testing.T, balance uint64, asset string, tendermintAddress string) *multisigwallet.Wallet {
	wallet := newTestWallet(t, strconv.Itoa(rand.Int()))
	issueBytes, err := wallet.Issue(balance, asset)
	broadcast(tendermintAddress, issueBytes)
	assert.NoError(t, err)
	return wallet
}

func closeWallets(wallets []*multisigwallet.Wallet) {
	for _, wallet := range wallets {
		wallet.Close()
	}
}

func testDbDir(walletName string) string {
	var usr, _ = user.Current()
	return filepath.Join(usr.HomeDir, ".mw_test_"+walletName)
}

func newTestWallet(t *testing.T, walletName string) (w *multisigwallet.Wallet) {
	dir := testDbDir(walletName)

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err = multisigwallet.NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)

	_, err = w.InitMasterKey("")
	assert.NoError(t, err)

	return
}
