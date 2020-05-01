package ledger

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

func Parse(bytes []byte) (tx *Transaction, issue *Issue, err error) {
	tx = &Transaction{}
	issue = &Issue{}

	errTx := json.Unmarshal(bytes, tx)
	errIssue := json.Unmarshal(bytes, issue)

	if errTx == nil && tx.Body.Kernels != nil && len(tx.Body.Kernels) > 0 {
		return tx, nil, nil
	} else if errIssue == nil && issue.Asset != "" {
		return nil, issue, nil
	} else {
		return nil, nil, errors.New(fmt.Sprintf("cannot parse neither to Transaction nor to Issue %v %v", errTx, errIssue))
	}
}

func ValidateTransaction(ledgerTx *Transaction) (err error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate")
	}
	defer secp256k1.ContextDestroy(context)

	tx := &ledgerTx.Transaction

	errSig := validateSignature(context, tx)
	errPrf := validateBulletproofs(context, tx.Body.Outputs)
	errSum := validateCommitmentsSum(context, tx)

	var errs []string
	if errSig != nil {
		errs = append(errs, "validateSignature")
	}
	if errSum != nil {
		errs = append(errs, "validateCommitmentsSum")
	}
	if errPrf != nil {
		errs = append(errs, "validateBulletproofs")
	}

	if len(errs) > 0 {
		return errors.Errorf("Transaction validation failed [%s]", strings.Join(errs, ", "))
	}

	return nil
}

func ValidateIssue(issue *Issue) error {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	err = validateBulletproofs(context, []core.Output{issue.Output})
	if err != nil {
		return errors.Wrap(err, "cannot validateBulletproofs")
	}

	// commit to issue value with zero blind 0*G + V*H
	valueBlind := [32]byte{} // zero
	valueCommit, err := secp256k1.Commit(context, valueBlind[:], issue.Value, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return errors.Wrap(err, "cannot Commit")
	}

	// issue kernel excess should be a commit to issue blind with zero value R*G + 0*H
	excess, err := secp256k1.CommitmentFromString(issue.Kernel.Excess)
	if err != nil {
		return errors.Wrap(err, "cannot CommitmentFromString")
	}

	// sum of commitment to value should be the issue output commit: I = (0*G + V*H) + (R*G + 0*H) = R*G + V*H
	sum, err := secp256k1.CommitSum(context, []*secp256k1.Commitment{excess, valueCommit}, []*secp256k1.Commitment{})
	if err != nil {
		return errors.Wrap(err, "cannot CommitSum")
	}

	// verify that equality
	if sum.String() != issue.Output.Commit {
		return errors.Wrap(err, "kernel excess verification failed")
	}

	return nil
}

func ValidateTransactionBytes(txBytes []byte) (ledgerTx *Transaction, err error) {
	ledgerTx = &Transaction{}

	err = json.Unmarshal(txBytes, ledgerTx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to Transaction")
	}

	err = ValidateTransaction(ledgerTx)

	return
}

func ValidateIssueBytes(issueBytes []byte) (ledgerIssue *Issue, err error) {
	ledgerIssue = &Issue{}

	err = json.Unmarshal(issueBytes, ledgerIssue)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to Issue")
	}

	err = ValidateIssue(ledgerIssue)

	return
}

func ValidateStateBytes(outputBytes []byte, kernelBytes []byte, assetBytes []byte) error {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate")
	}
	defer secp256k1.ContextDestroy(context)

	var outputs []core.Output

	err = json.Unmarshal(outputBytes, &outputs)
	if err != nil {
		return errors.Wrap(err, "cannot unmarshal json to outputs")
	}

	var kernels []core.TxKernel

	err = json.Unmarshal(kernelBytes, &kernels)
	if err != nil {
		return errors.Wrap(err, "cannot unmarshal json to kernels")
	}

	var assets map[string]uint64

	err = json.Unmarshal(assetBytes, &assets)
	if err != nil {
		return errors.Wrap(err, "cannot unmarshal json to assets")
	}

	outputCommitments := make([]*secp256k1.Commitment, 0)
	excessCommitments := make([]*secp256k1.Commitment, 0)

	scratch, err := secp256k1.ScratchSpaceCreate(context, 1024*4096)
	if err != nil {
		return errors.Wrap(err, "cannot ScratchSpaceCreate")
	}

	bulletproofGenerators, err := secp256k1.BulletproofGeneratorsCreate(context, &secp256k1.GeneratorG, 256)
	if bulletproofGenerators == nil {
		return errors.Wrap(err, "cannot BulletproofGeneratorsCreate")
	}

	for i, output := range outputs {
		err := validateBulletproof(context, output, scratch, bulletproofGenerators)
		if err != nil {
			return errors.Wrapf(err, "cannot validateBulletproof output #%d: %v", i, output)
		}

		com, err := secp256k1.CommitmentFromString(output.Commit)
		if err != nil {
			return errors.Wrapf(err, "cannot CommitmentFromString output #%d: %v", i, output)
		}
		outputCommitments = append(outputCommitments, com)
	}

	for i, kernel := range kernels {
		com, err := secp256k1.CommitmentFromString(kernel.Excess)
		if err != nil {
			return errors.Wrapf(err, "cannot CommitmentFromString kernel #%d: %v", i, kernel)
		}
		excessCommitments = append(excessCommitments, com)
	}

	// subtract all kernel excesses (from issues and transfers) from all remaining outputs
	// sum(O) - (sum(KE) + sum(offset)*G + sum(KEI))
	sumCommitment, err := secp256k1.CommitSum(context, outputCommitments, excessCommitments)
	if err != nil {
		return errors.Wrap(err, "cannot CommitSum outputCommitments, excessCommitments")
	}

	var totalIssues uint64
	for _, total := range assets {
		totalIssues += total
	}

	// commitment to total tokens issued is with a zero blind TI = 0*G + totalIssues*H
	//totalIssues := uint64(2)
	totalIssuesBlind := [32]byte{} // zero
	totalIssuesCommitment, err := secp256k1.Commit(context, totalIssuesBlind[:], totalIssues, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return errors.Wrap(err, "cannot Commit totalIssues")
	}

	// difference of remaining outputs and all excesses should equal to the commitment to value of total issued;
	// ex. for one issue I and one transfer from I to O:
	// sum(O) - sum(KE) = O - KE - KEI = RO*G + VO*H - (RO*G + VO*H - RI*G - VI*H) - (RI*G + 0*H) = 0*G + VI*H
	if sumCommitment.String() != totalIssuesCommitment.String() {
		return errors.Errorf("difference of outputs and kernel excesses does not equal to the total of issued assets=%d", totalIssues)
	}

	return nil
}

func validateSignature(context *secp256k1.Context, tx *core.Transaction) error {
	if len(tx.Body.Kernels) < 1 {
		return errors.New("no entries in Kernels")
	}

	excessSigBytes, err := hex.DecodeString(tx.Body.Kernels[0].ExcessSig)
	if err != nil {
		return errors.Wrap(err, "cannot decode hex ExcessSig")
	}
	excessSig, err := secp256k1.AggsigSignatureParse(context, excessSigBytes)
	if err != nil {
		return errors.Wrap(err, "cannot parse compact ExcessSig")
	}

	excessBytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)
	if err != nil {
		return errors.Wrap(err, "cannot decode hex Excess")
	}
	excessCommitment, err := secp256k1.CommitmentParse(context, excessBytes[:])
	if err != nil {
		return errors.Wrap(err, "CommitmentParse failed")
	}
	excessCommitmentAsPublicKey, err := secp256k1.CommitmentToPublicKey(context, excessCommitment)
	if err != nil {
		return errors.Wrap(err, "CommitmentToPublicKey failed")
	}

	msg := KernelSignatureMessage(tx.Body.Kernels[0])

	err = secp256k1.AggsigVerifySingle(
		context,
		excessSig,
		msg,
		nil,
		excessCommitmentAsPublicKey,
		excessCommitmentAsPublicKey,
		nil,
		false)
	if err != nil {
		return errors.Wrap(err, "AggsigVerifySingle failed")
	}

	return nil
}

// msg = hash(features)                       for coinbase kernels
//       hash(features || fee)                for plain kernels
//       hash(features || fee || lock_height) for height locked kernels
func KernelSignatureMessage(kernel core.TxKernel) []byte {

	featuresBytes := []byte{byte(kernel.Features)}
	feeBytes := make([]byte, 8)
	lockHeightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(feeBytes, uint64(kernel.Fee))
	binary.BigEndian.PutUint64(lockHeightBytes, uint64(kernel.LockHeight))

	hash, _ := blake2b.New256(nil)
	hash.Write(featuresBytes)
	if kernel.Features == core.PlainKernel {
		hash.Write(feeBytes)
	} else if kernel.Features == core.HeightLockedKernel {
		hash.Write(feeBytes)
		hash.Write(lockHeightBytes)
	}
	return hash.Sum(nil)
}

func CalculateExcess(
	context *secp256k1.Context,
	tx *core.Transaction,
	fee uint64,
) (
	kernelExcess *secp256k1.Commitment,
	err error,
) {
	var inputCommitments, outputCommitments []*secp256k1.Commitment

	// collect input commitments
	for _, input := range tx.Body.Inputs {
		com, err := secp256k1.CommitmentFromString(input.Commit) // secp256k1.CommitmentParse(context, secp256k1.Unhex(input.Commit))
		if err != nil {
			return nil, errors.Wrap(err, "error parsing input commitment")
		}
		inputCommitments = append(inputCommitments, com)
	}

	// collect output commitments
	for _, output := range tx.Body.Outputs {
		com, err := secp256k1.CommitmentFromString(output.Commit)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing output commitment")
		}
		outputCommitments = append(outputCommitments, com)
	}

	// add fee output into appropriate collection
	//TODO explore logic of negative fee
	if fee != 0 {
		//TODO validator needs to save his fee output
		feeBlind := [32]byte{} // zero
		feeCommitment, err := secp256k1.Commit(context, feeBlind[:], fee, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
		if err != nil {
			return nil, errors.Wrap(err, "error calculating fee commitment")
		}
		if fee > 0 {
			// add to outputCommitments if positive
			outputCommitments = append(outputCommitments, feeCommitment)
		} else {
			// add to inputCommitments if negative
			inputCommitments = append(inputCommitments, feeCommitment)
		}
	}

	// add kernel offset to inputs
	offsetBytes, _ := hex.DecodeString(tx.Offset)
	kernelOffset, err := secp256k1.Commit(context, offsetBytes, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return nil, errors.Wrap(err, "error calculating offset commitment")
	}
	inputCommitments = append(inputCommitments, kernelOffset)

	// sum up the commitments
	kernelExcess, err = secp256k1.CommitSum(context, outputCommitments, inputCommitments)
	if err != nil {
		return
	}

	return
}

func validateCommitmentsSum(
	context *secp256k1.Context,
	tx *core.Transaction,
) error {
	if len(tx.Body.Kernels) != 1 {
		return errors.New("expected one kernel in the slate")
	}
	kernel := tx.Body.Kernels[0]

	kernelExcess, err := CalculateExcess(context, tx, uint64(kernel.Fee))
	if err != nil {
		return errors.Wrap(err, "cannot calculate kernel excess")
	}

	// compare calculated excess with the one stored in the tx kernel
	if kernelExcess.String() != kernel.Excess {
		return errors.Wrap(err, "kernel excess verification failed")
	}

	return nil
}

func validateBulletproofs(
	context *secp256k1.Context,
	outputs []core.Output,
) error {
	scratch, err := secp256k1.ScratchSpaceCreate(context, 1024*4096)
	if err != nil {
		return errors.Wrap(err, "cannot ScratchSpaceCreate")
	}

	bulletproofGenerators, err := secp256k1.BulletproofGeneratorsCreate(context, &secp256k1.GeneratorG, 256)
	if bulletproofGenerators == nil {
		return errors.Wrap(err, "cannot BulletproofGeneratorsCreate")
	}

	for i, output := range outputs {
		err := validateBulletproof(context, output, scratch, bulletproofGenerators)
		if err != nil {
			return errors.Wrapf(err, "cannot validateBulletproof output #%d: %v", i, output)
		}
	}

	return nil
}

func validateBulletproof(
	context *secp256k1.Context,
	output core.Output,
	scratch *secp256k1.ScratchSpace,
	generators *secp256k1.BulletproofGenerators,
) error {
	proof, err := hex.DecodeString(output.Proof)
	if err != nil {
		return errors.Wrap(err, "cannot decode Proof from hex")
	}

	commit, err := secp256k1.CommitmentFromString(output.Commit)
	if err != nil {
		return errors.Wrap(err, "cannot decode Commit from hex")
	}

	err = secp256k1.BulletproofRangeproofVerifySingle(
		context,
		scratch,
		generators,
		proof,
		commit,
		nil,
	)
	if err != nil {
		return errors.New("cannot BulletproofRangeproofVerify")
	}

	return nil
}
