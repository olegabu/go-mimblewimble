package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/stretchr/testify/assert"
)

func TestWalletSendReceive(t *testing.T) {
	w := newTestWallet(t, "test")
	defer w.Close()

	for _, value := range []uint64{1, 2, 3} {
		_, err := w.Issue(value, "cash")
		assert.NoError(t, err)
	}

	err := w.Print()
	assert.NoError(t, err)

	tx := testSendReceive(t, w, 4, "cash")

	// take 3 inputs 1+2+3 for 2 outputs: receiver 4 and change 2
	assert.Equal(t, 3, len(tx.Body.Inputs))
	assert.Equal(t, 2, len(tx.Body.Outputs))

	tx = testSendReceive(t, w, 6, "cash")

	// take 2 inputs 2+4 for 1 output: receiver 6
	assert.Equal(t, 2, len(tx.Body.Inputs))
	assert.Equal(t, 1, len(tx.Body.Outputs))
}

func TestWalletInvoicePay(t *testing.T) {
	w := newTestWallet(t, "test")
	defer w.Close()

	for _, value := range []uint64{1, 2, 3} {
		_, err := w.Issue(value, "cash")
		assert.NoError(t, err)
	}

	err := w.Print()
	assert.NoError(t, err)

	tx := testInvoicePay(t, w, 4, "cash")

	// take 3 inputs 1+2+3 for 2 outputs: receiver 4 and change 2
	assert.Equal(t, 3, len(tx.Body.Inputs))
	assert.Equal(t, 2, len(tx.Body.Outputs))

	tx = testInvoicePay(t, w, 6, "cash")

	// take 2 inputs 2+4 for 1 output: receiver 6
	assert.Equal(t, 2, len(tx.Body.Inputs))
	assert.Equal(t, 1, len(tx.Body.Outputs))
}

func TestWalletIssue(t *testing.T) {
	w := newTestWallet(t, "test")
	defer w.Close()

	issueBytes, err := w.Issue(1, "cash")
	assert.NoError(t, err)

	err = w.Print()
	assert.NoError(t, err)

	_, err = ledger.ValidateIssueBytes(issueBytes)
	assert.NoError(t, err)
}

func TestWalletIssueChangeAssetBlind(t *testing.T) {
	w := newTestWallet(t, "test")
	defer w.Close()

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.NoError(t, err)
	defer secp256k1.ContextDestroy(context)

	issueBytes, err := w.Issue(1, "cash")
	assert.NoError(t, err)

	err = w.Print()
	assert.NoError(t, err)

	issue := ledger.Issue{}
	err = json.Unmarshal(issueBytes, &issue)
	assert.NoError(t, err)

	seed := ledger.AssetSeed("cash")

	// change asset blind and expect to fail bulletproof validation
	assetBlindInvalid, _ := w.Nonce(context)

	assetCommitment, err := secp256k1.GeneratorGenerateBlinded(context, seed, assetBlindInvalid[:])
	assert.NoError(t, err)

	issue.Output.AssetCommit = assetCommitment.String()

	issueBytes, err = json.Marshal(issue)
	assert.NoError(t, err)

	_, err = ledger.ValidateIssueBytes(issueBytes)
	assert.Error(t, err)

	// change asset blind back to the one saved in the wallet and expect to pass validation
	assetBlindValid, _ := w.Secret(context, 1)

	assetCommitment, err = secp256k1.GeneratorGenerateBlinded(context, seed, assetBlindValid[:])
	assert.NoError(t, err)

	issue.Output.AssetCommit = assetCommitment.String()

	issueBytes, err = json.Marshal(issue)
	assert.NoError(t, err)

	_, err = ledger.ValidateIssueBytes(issueBytes)
	assert.NoError(t, err)
}

func TestWalletInvoicePaySingle(t *testing.T) {
	w := newTestWallet(t, "test")
	defer w.Close()

	for _, value := range []uint64{1, 2} {
		_, err := w.Issue(value, "cash")
		assert.NoError(t, err)
	}

	err := w.Print()
	assert.NoError(t, err)

	tx := testInvoicePay(t, w, 1, "cash")

	assert.Equal(t, 1, len(tx.Body.Inputs))
	assert.Equal(t, 1, len(tx.Body.Outputs))
}

func TestWalletExchange(t *testing.T) {
	w := newTestWallet(t, "test")
	defer w.Close()

	for _, value := range []uint64{1, 2, 3} {
		_, err := w.Issue(value, "cash")
		assert.NoError(t, err)
	}

	for _, value := range []uint64{1, 2} {
		_, err := w.Issue(value, "apple")
		assert.NoError(t, err)
	}

	err := w.Print()
	assert.NoError(t, err)

	sendAmount := uint64(6)
	sendAsset := "cash"

	receiveAmount := uint64(3)
	receiveAsset := "apple"

	slateBytes, err := w.Send(sendAmount, sendAsset, receiveAmount, receiveAsset)
	assert.NoError(t, err)
	fmt.Println("send " + string(slateBytes))

	err = w.Print()
	assert.NoError(t, err)

	responseSlateBytes, err := w.Respond(slateBytes)
	assert.NoError(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	err = w.Print()
	assert.NoError(t, err)

	txBytes, err := w.Finalize(responseSlateBytes)
	assert.NoError(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Print()
	assert.NoError(t, err)

	tx, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)

	err = w.Confirm([]byte(tx.ID.String()))
	assert.NoError(t, err)

	err = w.Print()
	assert.NoError(t, err)

	// 5 inputs 1+2+3 cash 1+2 apples, 2 outputs: 6 cash 3 apple
	assert.Equal(t, 5, len(tx.Body.Inputs))
	assert.Equal(t, 2, len(tx.Body.Outputs))
}

func TestTotalIssues(t *testing.T) {
	w := newTestWallet(t, "test")
	defer w.Close()

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	assert.NoError(t, err)
	defer secp256k1.ContextDestroy(context)

	var outputCommitments []*secp256k1.Commitment
	var excessCommitments []*secp256k1.Commitment

	var totalCashIssues uint64

	// issue several tokens of the same asset, sum total number issued,
	// collect issue kernel excesses into excessCommitments;
	// issue kernel excess is a public blind, as input value to an issue is zero: KEI = RI*G + 0*H
	for _, value := range []uint64{1, 2, 3} {
		totalCashIssues += value
		issueBytes, err := w.Issue(value, "cash")
		assert.NoError(t, err)
		issue := ledger.Issue{}
		err = json.Unmarshal(issueBytes, &issue)
		assert.NoError(t, err)
		issueExcess, err := secp256k1.CommitmentFromString(issue.Kernel.Excess)
		assert.NoError(t, err)
		excessCommitments = append(excessCommitments, issueExcess)
	}

	// commitment to total tokens issued is with a zero blind TI = 0*G + totalCashIssues*hash("cash")*H
	totalCashIssuesCommitment, err := ledger.MultiplyValueAssetGenerator(totalCashIssues, "cash")
	assert.NoError(t, err)

	var totalAppleIssues uint64

	// issue several tokens of another asset, sum total number issued
	for _, value := range []uint64{1, 2, 3} {
		totalAppleIssues += value
		issueBytes, err := w.Issue(value, "apple")
		assert.NoError(t, err)
		issue := ledger.Issue{}
		err = json.Unmarshal(issueBytes, &issue)
		assert.NoError(t, err)
		issueExcess, err := secp256k1.CommitmentFromString(issue.Kernel.Excess)
		assert.NoError(t, err)
		excessCommitments = append(excessCommitments, issueExcess)

		issueCommit, err := secp256k1.CommitmentFromString(issue.Output.Commit)
		assert.NoError(t, err)
		outputCommitments = append(outputCommitments, issueCommit)
	}

	// commitment to total coins issued is with a zero blind TI = 0*G + totalAppleIssues*hash("apple")*H
	totalAppleIssuesCommitment, err := ledger.MultiplyValueAssetGenerator(totalAppleIssues, "apple")
	assert.NoError(t, err)

	tx := testSendReceive(t, w, 5, "cash")

	// collect outputs into outputCommitments
	for _, output := range tx.Body.Outputs {
		com, err := secp256k1.CommitmentFromString(output.Commit)
		assert.NoError(t, err)
		outputCommitments = append(outputCommitments, com)
	}

	// add transaction kernel excess to excessCommitments
	txExcess, err := secp256k1.CommitmentFromString(tx.Body.Kernels[0].Excess)
	assert.NoError(t, err)
	excessCommitments = append(excessCommitments, txExcess)

	// add kernel offset to excessCommitments
	offsetBytes, _ := hex.DecodeString(tx.Offset)
	kernelOffset, err := secp256k1.Commit(context, offsetBytes, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	excessCommitments = append(excessCommitments, kernelOffset)

	// subtract all kernel excesses (from issues and transfers) from all remaining outputs
	// sum(outputs) - (sum(KE) + sum(offset)*G + sum(KEI))
	sumCommitment, err := secp256k1.CommitSum(context, outputCommitments, excessCommitments)
	assert.NoError(t, err)

	// sum up commitments to total number of both assets issued
	totalIssuesCommitment, err := secp256k1.CommitSum(context, []*secp256k1.Commitment{totalCashIssuesCommitment, totalAppleIssuesCommitment}, nil)
	assert.NoError(t, err)

	// difference of remaining outputs and all excesses should equal to the commitment to value of total issued;
	// ex. for one issue I and one transfer from I to O:
	// sum(O) - sum(KE) = O - KE - KEI = RO*G + VO*H - (RO*G + VO*H - RI*G - VI*H) - (RI*G + 0*H) = 0*G + VI*H
	assert.Equal(t, sumCommitment.String(), totalIssuesCommitment.String())
}

func testSendReceive(t *testing.T, w *Wallet, amount uint64, asset string) (tx *ledger.Transaction) {
	slateBytes, err := w.Send(amount, asset, 0, "")
	assert.NoError(t, err)
	fmt.Println("send " + string(slateBytes))

	err = w.Print()
	assert.NoError(t, err)

	responseSlateBytes, err := w.Respond(slateBytes)
	assert.NoError(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	err = w.Print()
	assert.NoError(t, err)

	txBytes, err := w.Finalize(responseSlateBytes)
	assert.NoError(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Print()
	assert.NoError(t, err)

	tx, err = ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)

	err = w.Confirm([]byte(tx.ID.String()))
	assert.NoError(t, err)

	err = w.Print()
	assert.NoError(t, err)

	return
}

func testInvoicePay(t *testing.T, w *Wallet, amount uint64, asset string) (tx *ledger.Transaction) {
	slateBytes, err := w.Send(0, "", amount, asset)
	//slateBytes, err := w.Invoice(amount, asset)
	assert.NoError(t, err)
	fmt.Println("invoice " + string(slateBytes))

	err = w.Print()
	assert.NoError(t, err)

	responseSlateBytes, err := w.Respond(slateBytes)
	assert.NoError(t, err)
	fmt.Println("pay " + string(responseSlateBytes))

	err = w.Print()
	assert.NoError(t, err)

	txBytes, err := w.Finalize(responseSlateBytes)
	assert.NoError(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Print()
	assert.NoError(t, err)

	tx, err = ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)

	err = w.Confirm([]byte(tx.ID.String()))
	assert.NoError(t, err)

	err = w.Print()
	assert.NoError(t, err)

	return
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
