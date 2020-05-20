package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/olegabu/go-mimblewimble/ledger"
)

func testDbDir() string {
	var usr, _ = user.Current()
	return filepath.Join(usr.HomeDir, ".mw_test")
}

func TestWalletSendReceive(t *testing.T) {
	w := newTestWallet(t)
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
	w := newTestWallet(t)
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

func TestWalletInvoicePaySingle(t *testing.T) {
	w := newTestWallet(t)
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
	w := newTestWallet(t)
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
	w := newTestWallet(t)
	defer w.Close()

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
	kernelOffset, err := secp256k1.Commit(w.context, offsetBytes, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	excessCommitments = append(excessCommitments, kernelOffset)

	// subtract all kernel excesses (from issues and transfers) from all remaining outputs
	// sum(outputs) - (sum(KE) + sum(offset)*G + sum(KEI))
	sumCommitment, err := secp256k1.CommitSum(w.context, outputCommitments, excessCommitments)
	assert.NoError(t, err)

	// sum up commitments to total number of both assets issued
	totalIssuesCommitment, err := secp256k1.CommitSum(w.context, []*secp256k1.Commitment{totalCashIssuesCommitment, totalAppleIssuesCommitment}, nil)
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

func TestPrint(t *testing.T) {
	dir := testDbDir()
	w, err := NewWallet(dir)
	assert.NoError(t, err)
	defer w.Close()
	err = w.Print()
	assert.NoError(t, err)
}
