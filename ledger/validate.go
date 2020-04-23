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
	publicKey, err := secp256k1.CommitmentToPublicKey(context, excessCommitment)
	if err != nil {
		return errors.Wrap(err, "CommitmentToPublicKey failed")
	}

	msg := KernelSignatureMessage(tx.Body.Kernels[0])

	err = secp256k1.AggsigVerifySingle(
		context,
		excessSig,
		msg,
		nil,
		publicKey,
		publicKey,
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

	// add a fee commitment into appropriate collection
	if fee != 0 {
		var zblind [32]byte
		com, err := secp256k1.Commit(context, zblind[:], fee, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
		if err != nil {
			return nil, errors.Wrap(err, "error calculating fee commitment")
		}
		if fee > 0 {
			// add to outputCommitments if positive
			outputCommitments = append(outputCommitments, com)
		} else {
			// add to inputCommitments if negative
			inputCommitments = append(inputCommitments, com)
		}
	}

	// subtract the kernel_excess (built from kernel_offset)
	offsetbytes, _ := hex.DecodeString(tx.Offset)
	kernelOffset, err := secp256k1.Commit(context, offsetbytes, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
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

/*
	var outputs, inputs []*secp256k1.Commitment

	for i, input := range tx.Body.Inputs {
		commitmentBytes, err := hex.DecodeString(input.Commit)
		if err != nil {
			return errors.Wrapf(err, "cannot decode input.Commit from hex for input %v", i)
		}

		commitment, err := secp256k1.CommitmentParse(context, commitmentBytes)
		if err != nil {
			return errors.Wrapf(err, "cannot parse commitmentBytes for input %v", i)
		}

		inputs = append(inputs, commitment)
	}

	for i, output := range tx.Body.Outputs {
		commitmentBytes, err := hex.DecodeString(output.Commit)
		if err != nil {
			return errors.Wrapf(err, "cannot decode input.Commit from hex for output %v", i)
		}

		commitment, err := secp256k1.CommitmentParse(context, commitmentBytes)
		if err != nil {
			return errors.Wrapf(err, "cannot parse commitmentBytes for output %v", i)
		}

		outputs = append(outputs, commitment)
	}

	// verify kernel sums

	var zeroBlindingFactor [32]byte

	if len(tx.Body.Kernels) == 0 {
		return errors.New("no Kernel objects found in the slate")
	}

	// NB: FEE = Overage (grin core terminology)
	fee := uint64(tx.Body.Kernels[0].Fee)
	if fee != 0 {
		feeCommitment, err := secp256k1.Commit(context, zeroBlindingFactor[:], fee, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
		if err != nil {
			return errors.New("cannot calculate feeCommitment")
		}
		outputs = append(outputs, feeCommitment)
	}

	// the first part of equality to check
	// InputCommitmentsSum - (OutputCommitments + FeeCommitments)
	commitmentsSum, err := secp256k1.CommitSum(context, inputs, outputs)
	if err != nil {
		return errors.New("cannot calculate commitmentsSum")
	}

	// serialize it to simplify equality check
	serializedCommitmentsSum, err := secp256k1.CommitmentSerialize(context, commitmentsSum)
	if err != nil {
		return errors.New("cannot serialize commitmentsSum")
	}

	// calculate the second part
	offsetBytes, err := hex.DecodeString(tx.Offset)
	if err != nil {
		return errors.Wrap(err, "cannot decode tx.Offset from hex")
	}

	excessBytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)
	if err != nil {
		return errors.Wrap(err, "cannot decode tx.Body.Kernels[0].Excess from hex")
	}

	//var offset32 [32]byte
	//copy(offset32[:], offsetBytes[:32])

	offsetCommitment, err := secp256k1.Commit(context, offsetBytes[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return errors.New("cannot calculate offsetCommitment")
	}

	excessCommitment, err := secp256k1.CommitmentParse(context, excessBytes[:])
	if err != nil {
		return errors.New("cannot parse excessBytes")
	}

	kernelExcess, err := secp256k1.CommitSum(context, make([]*secp256k1.Commitment, 0), (&([2]*secp256k1.Commitment{offsetCommitment, excessCommitment}))[:])
	if err != nil {
		return errors.New("cannot calculate kernelExcess")
	}

	serializedKernelExcess, err := secp256k1.CommitmentSerialize(context, kernelExcess)
	if err != nil {
		return errors.New("cannot serialize kernelExcess")
	}

	if bytes.Compare(serializedKernelExcess[:], serializedCommitmentsSum[:]) != 0 {
		return errors.New("serializedKernelExcess not equal to serializedCommitmentsSum")
	}

	return nil
}
*/

func validateCommitmentsSum(
	context *secp256k1.Context,
	tx *core.Transaction,
) (
	err error,
) {
	if len(tx.Body.Kernels) == 0 {
		return errors.New("no kernels found in the slate")
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

	return nil // no errror
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
