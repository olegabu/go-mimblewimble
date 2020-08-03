package ledger

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func AssetSeed(asset string) []byte {
	assetHash, _ := blake2b.New256(nil)
	assetHash.Write([]byte(asset))
	return assetHash.Sum(nil)[:32]
}

func MultiplyValueAssetGenerator(value uint64, asset string) (com *secp256k1.Commitment, err error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot ContextCreate")
		return
	}
	defer secp256k1.ContextDestroy(context)

	var zero32 [32]byte
	zero := zero32[:]

	seed := AssetSeed(asset)

	assetCommitment, err := secp256k1.GeneratorGenerateBlinded(context, seed, zero)
	if err != nil {
		err = errors.Wrap(err, "cannot GeneratorGenerateBlinded")
		return
	}

	com, err = secp256k1.Commit(context, zero, value, assetCommitment, &secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot Commit")
		return
	}

	return
}

func ValidateTransaction(tx *Transaction) (err error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate")
	}
	defer secp256k1.ContextDestroy(context)

	var errs []error
	if err := validateCommitmentsSum(context, tx); err != nil {
		errs = append(errs, errors.Wrap(err, "validateCommitmentsSum"))
	}
	if err := validateSignature(context, tx); err != nil {
		errs = append(errs, errors.Wrap(err, "validateSignature"))
	}
	if err := validateBulletproofs(context, tx.Body.Outputs); err != nil {
		errs = append(errs, errors.Wrap(err, "validateBulletproofs"))
	}
	if err := validateSurjectionProofs(context, tx.Body.Outputs, tx.Body.Inputs); err != nil {
		errs = append(errs, errors.Wrap(err, "validateSurjectionProofs"))
	}

	if len(errs) > 0 {
		return errors.Errorf("Transaction validation failed %v", errs)
	}

	return nil
}

func ValidateIssue(issue *Issue) error {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	err = validateBulletproofs(context, []Output{issue.Output})
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

func ValidateState(outputs []Output, kernels []TxKernel, assets map[string]uint64) (msg string, err error) {
	var totalIssues uint64
	for _, t := range assets {
		totalIssues += t
	}

	msg = fmt.Sprintf("%d outputs, %d kernels, %d types of assets, %d total assets", len(outputs), len(kernels), len(assets), totalIssues)

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot ContextCreate")
		return
	}
	defer secp256k1.ContextDestroy(context)

	outputCommitments := make([]*secp256k1.Commitment, 0)
	excessCommitments := make([]*secp256k1.Commitment, 0)
	issueCommitments := make([]*secp256k1.Commitment, 0)

	scratch, err := secp256k1.ScratchSpaceCreate(context, 1024*4096)
	if err != nil {
		err = errors.Wrap(err, "cannot ScratchSpaceCreate")
		return
	}

	bulletproofGenerators, e := secp256k1.BulletproofGeneratorsCreate(context, &secp256k1.GeneratorG, 256)
	if bulletproofGenerators == nil || e != nil {
		err = errors.Wrap(err, "cannot BulletproofGeneratorsCreate")
		return
	}

	for i, output := range outputs {
		e := validateBulletproof(context, output, scratch, bulletproofGenerators)
		if e != nil {
			err = errors.Wrapf(e, "cannot validateBulletproof output #%d: %v", i, output)
			return
		}

		com, e := secp256k1.CommitmentFromString(output.Commit)
		if e != nil {
			err = errors.Wrapf(e, "cannot CommitmentFromString output #%d: %v", i, output)
			return
		}
		outputCommitments = append(outputCommitments, com)
	}

	for i, kernel := range kernels {
		com, e := secp256k1.CommitmentFromString(kernel.Excess)
		if e != nil {
			err = errors.Wrapf(e, "cannot CommitmentFromString kernel #%d: %v", i, kernel)
			return
		}
		excessCommitments = append(excessCommitments, com)
	}

	// subtract all kernel excesses (from issues and transfers) from all remaining outputs
	// sum(O) - (sum(KE) + sum(offset)*G + sum(KEI))
	sumCommitment, err := secp256k1.CommitSum(context, outputCommitments, excessCommitments)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum outputCommitments, excessCommitments")
		return
	}

	for asset, total := range assets {
		issueCommitment, e := MultiplyValueAssetGenerator(total, asset)
		if e != nil {
			err = errors.Wrap(e, "cannot MultiplyValueAssetGenerator")
			return
		}
		issueCommitments = append(issueCommitments, issueCommitment)
	}

	// sum up commitments to total number of all assets issued
	totalIssuesCommitment, err := secp256k1.CommitSum(context, issueCommitments, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum issueCommitments")
		return
	}

	// difference of remaining outputs and all excesses should equal to the commitment to value of total issued;
	// ex. for one issue I and one transfer from I to O:
	// sum(O) - sum(KE) = O - KE - KEI = RO*G + VO*H - (RO*G + VO*H - RI*G - VI*H) - (RI*G + 0*H) = 0*G + VI*H
	if sumCommitment.String() != totalIssuesCommitment.String() {
		err = errors.Errorf("difference of outputs and kernel excesses does not equal to the total of issued assets=%d", totalIssues)
		return
	}

	return
}

func validateSignature(context *secp256k1.Context, tx *Transaction) error {
	if len(tx.Body.Kernels) != 1 {
		return errors.New("expected one kernel in transaction")
	}

	kernel := tx.Body.Kernels[0]

	excessSigBytes, err := hex.DecodeString(kernel.ExcessSig)
	if err != nil {
		return errors.Wrap(err, "cannot decode hex ExcessSig")
	}
	excessSig, err := secp256k1.AggsigSignatureParse(context, excessSigBytes)
	if err != nil {
		return errors.Wrap(err, "cannot parse compact ExcessSig")
	}

	excessBytes, err := hex.DecodeString(kernel.Excess)
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

	msg := KernelSignatureMessage(kernel)

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
func KernelSignatureMessage(kernel TxKernel) []byte {

	featuresBytes := []byte{byte(kernel.Features)}
	feeBytes := make([]byte, 8)
	lockHeightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(feeBytes, uint64(kernel.Fee))
	binary.BigEndian.PutUint64(lockHeightBytes, uint64(kernel.LockHeight))

	hash, _ := blake2b.New256(nil)
	hash.Write(featuresBytes)
	if kernel.Features == PlainKernel {
		hash.Write(feeBytes)
	} else if kernel.Features == HeightLockedKernel {
		hash.Write(feeBytes)
		hash.Write(lockHeightBytes)
	}
	return hash.Sum(nil)
}

func CalculateExcess(
	context *secp256k1.Context,
	inputCommitments []*secp256k1.Commitment,
	outputCommitments []*secp256k1.Commitment,
	offsetBytes []byte,
	fee uint64,
) (
	kernelExcess *secp256k1.Commitment,
	err error,
) {
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

func validateCommitmentsSum(context *secp256k1.Context, tx *Transaction) error {
	if len(tx.Body.Kernels) != 1 {
		return errors.New("expected one kernel in the slate")
	}
	kernel := tx.Body.Kernels[0]

	var inputCommitments, outputCommitments []*secp256k1.Commitment

	// collect input commitments
	for _, input := range tx.Body.Inputs {
		com, err := secp256k1.CommitmentFromString(input.Commit) // secp256k1.CommitmentParse(context, secp256k1.Unhex(input.Commit))
		if err != nil {
			return errors.Wrap(err, "error parsing input commitment")
		}
		inputCommitments = append(inputCommitments, com)
	}

	// collect output commitments
	for _, output := range tx.Body.Outputs {
		com, err := secp256k1.CommitmentFromString(output.Commit)
		if err != nil {
			return errors.Wrap(err, "error parsing output commitment")
		}
		outputCommitments = append(outputCommitments, com)
	}

	offsetBytes, err := hex.DecodeString(tx.Offset)
	if err != nil {
		return errors.Wrap(err, "cannot get offsetBytes")
	}

	kernelExcess, err := CalculateExcess(context, inputCommitments, outputCommitments, offsetBytes, uint64(kernel.Fee))
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
	outputs []Output,
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
	output Output,
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

	assetCommit, err := secp256k1.GeneratorFromString(output.AssetCommit)
	if err != nil {
		return errors.Wrap(err, "cannot decode AssetCommit from hex")
	}

	err = secp256k1.BulletproofRangeproofVerifySingleCustomGen(
		context,
		scratch,
		generators,
		proof,
		commit,
		nil,
		assetCommit,
	)
	if err != nil {
		return errors.Wrap(err, "cannot BulletproofRangeproofVerifySingleCustomGen")
	}

	return nil
}

func validateSurjectionProofs(
	context *secp256k1.Context,
	outputs []Output,
	inputs []Input,
) error {
	for i, output := range outputs {
		err := validateSurjectionProof(context, output, inputs)
		if err != nil {
			return errors.Wrapf(err, "cannot validateSurjectionProof output #%d: %v", i, output)
		}
	}

	return nil
}

func validateSurjectionProof(ctx *secp256k1.Context, output Output, inputs []Input) error {
	outputAssetCommitmentBytes, err := hex.DecodeString(output.AssetCommit)
	if err != nil {
		return errors.Wrapf(err, "cannot DecodeString outputAssetCommitmentBytes")
	}

	ephemeralOutputTag, err := secp256k1.GeneratorParse(ctx, outputAssetCommitmentBytes)
	if err != nil {
		return errors.Wrapf(err, "cannot GeneratorParse ephemeralOutputTag")
	}

	var ephemeralInputTags []*secp256k1.Generator
	for _, input := range inputs {
		var ephemeralInputTag *secp256k1.Generator
		var inputAssetCommitmentBytes []byte
		inputAssetCommitmentBytes, err = hex.DecodeString(input.AssetCommit)
		ephemeralInputTag, err = secp256k1.GeneratorParse(ctx, inputAssetCommitmentBytes)
		if err != nil {
			return errors.Wrapf(err, "cannot GeneratorParse ephemeralInputTag")
		}
		ephemeralInputTags = append(ephemeralInputTags, ephemeralInputTag)
	}

	assetProofBytes, err := hex.DecodeString(output.AssetProof)
	if err != nil {
		return errors.Wrapf(err, "cannot get assetProofBytes")
	}

	proof, err := secp256k1.SurjectionproofParse(ctx, assetProofBytes)
	if err != nil {
		return errors.Wrapf(err, "cannot SurjectionproofParse")
	}

	return secp256k1.SurjectionproofVerify(ctx, proof, ephemeralInputTags, ephemeralOutputTag)
}
