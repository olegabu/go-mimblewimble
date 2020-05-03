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

	err := w.Info()
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

	err := w.Info()
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

func TestTotalIssues(t *testing.T) {
	w := newTestWallet(t)
	defer w.Close()

	outputCommitments := make([]*secp256k1.Commitment, 0)
	excessCommitments := make([]*secp256k1.Commitment, 0)

	var totalIssues uint64

	// issue several tokens of the same asset, sum total number issued,
	// collect issue kernel excesses into excessCommitments;
	// issue kernel excess is a public blind, as input value to an issue is zero KEI = RI*G + 0*H
	for _, value := range []uint64{1, 2, 3} {
		totalIssues += value
		issueBytes, err := w.Issue(value, "cash")
		assert.NoError(t, err)
		issue := ledger.Issue{}
		err = json.Unmarshal(issueBytes, &issue)
		assert.NoError(t, err)
		issueExcess, err := secp256k1.CommitmentFromString(issue.Kernel.Excess)
		assert.NoError(t, err)
		excessCommitments = append(excessCommitments, issueExcess)
	}

	// commitment to total tokens issued is with a zero blind TI = 0*G + totalIssues*H
	totalIssuesBlind := [32]byte{} // zero
	totalIssuesCommitment, err := secp256k1.Commit(w.context, totalIssuesBlind[:], totalIssues, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)

	// transfer 5 out of total issued 6 to have 2 outputs: receiver 5 and change 1
	tx := testSendReceive(t, w, 5, "cash")

	// collect outputs into outputCommitments
	for _, output := range tx.Body.Outputs {
		com, err := secp256k1.CommitmentFromString(output.Commit)
		assert.NoError(t, err)
		outputCommitments = append(outputCommitments, com)
	}

	// add transfer transaction kernel excess to excessCommitments
	transferExcess, err := secp256k1.CommitmentFromString(tx.Body.Kernels[0].Excess)
	assert.NoError(t, err)
	excessCommitments = append(excessCommitments, transferExcess)

	// add kernel offset to excessCommitments
	offsetBytes, _ := hex.DecodeString(tx.Offset)
	kernelOffset, err := secp256k1.Commit(w.context, offsetBytes, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	excessCommitments = append(excessCommitments, kernelOffset)

	// subtract all kernel excesses (from issues and transfers) from all remaining outputs
	// sum(O) - (sum(KE) + sum(offset)*G + sum(KEI))
	sumCommitment, err := secp256k1.CommitSum(w.context, outputCommitments, excessCommitments)
	assert.NoError(t, err)

	// difference of remaining outputs and all excesses should equal to the commitment to value of total issued;
	// ex. for one issue I and one transfer from I to O:
	// sum(O) - sum(KE) = O - KE - KEI = RO*G + VO*H - (RO*G + VO*H - RI*G - VI*H) - (RI*G + 0*H) = 0*G + VI*H
	assert.Equal(t, sumCommitment.String(), totalIssuesCommitment.String())
}

func testSendReceive(t *testing.T, w *Wallet, amount uint64, asset string) (tx *ledger.Transaction) {
	slateBytes, err := w.Send(amount, asset)
	assert.NoError(t, err)
	fmt.Println("send " + string(slateBytes))

	err = w.Info()
	assert.NoError(t, err)

	responseSlateBytes, err := w.Receive(slateBytes)
	assert.NoError(t, err)
	fmt.Println("resp " + string(responseSlateBytes))

	err = w.Info()
	assert.NoError(t, err)

	txBytes, err := w.Finalize(responseSlateBytes)
	assert.NoError(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Info()
	assert.NoError(t, err)

	tx, err = ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)

	err = w.Confirm([]byte(tx.ID.String()))
	assert.NoError(t, err)

	err = w.Info()
	assert.NoError(t, err)

	return
}

func testInvoicePay(t *testing.T, w *Wallet, amount uint64, asset string) (tx *ledger.Transaction) {
	slateBytes, err := w.Invoice(amount, asset)
	assert.NoError(t, err)
	fmt.Println("invoice " + string(slateBytes))

	err = w.Info()
	assert.NoError(t, err)

	responseSlateBytes, err := w.Pay(slateBytes)
	assert.NoError(t, err)
	fmt.Println("pay " + string(responseSlateBytes))

	err = w.Info()
	assert.NoError(t, err)

	txBytes, err := w.Finalize(responseSlateBytes)
	assert.NoError(t, err)
	fmt.Println("tx   " + string(txBytes))

	err = w.Info()
	assert.NoError(t, err)

	tx, err = ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)

	err = w.Confirm([]byte(tx.ID.String()))
	assert.NoError(t, err)

	err = w.Info()
	assert.NoError(t, err)

	return
}

func TestInfo(t *testing.T) {
	dir := testDbDir()
	w, err := NewWallet(dir)
	assert.NoError(t, err)
	defer w.Close()
	err = w.Info()
	assert.NoError(t, err)
}
