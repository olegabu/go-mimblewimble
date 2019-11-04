package mw

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

func ValidateTransaction(txBytes []byte) (*core.Transaction, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	tx := &core.Transaction{}

	err = json.Unmarshal(txBytes, tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to Transaction")
	}

	err = validateSignature(context, tx)
	if err != nil {
		return tx, errors.Wrap(err, "cannot validateSignature")
	}

	err = validateCommitmentsSum(context, tx)
	if err != nil {
		return tx, errors.Wrap(err, "cannot validateCommitmentsSum")
	}

	err = validateBulletproofs(context, tx)
	if err != nil {
		return tx, errors.Wrap(err, "cannot validateBulletproofs")
	}

	return tx, nil
}

func validateSignature(context *secp256k1.Context, tx *core.Transaction) error {
	excessSigBytes, err := hex.DecodeString(tx.Body.Kernels[0].ExcessSig)
	if err != nil {
		return errors.Wrap(err, "cannot decode ExcessSig")
	}

	excessBytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)
	if err != nil {
		return errors.Wrap(err, "cannot decode Excess")
	}

	status, excessCommitment, err := secp256k1.CommitmentParse(context, excessBytes[:])
	if !status || err != nil {
		return errors.Wrap(err, "CommitmentParse failed")
	}

	status, publicKey, err := secp256k1.CommitmentToPublicKey(context, excessCommitment)
	if !status || err != nil {
		return errors.Wrap(err, "CommitmentToPublicKey failed")
	}

	features := []byte{byte(0)}
	fee := make([]byte, 8)
	binary.BigEndian.PutUint64(fee, uint64(tx.Body.Kernels[0].Fee))
	hash, _ := blake2b.New256(nil)
	hash.Write(features)
	hash.Write(fee)
	msg := hash.Sum(nil)

	status, err = secp256k1.AggsigVerifySingle(
		context,
		excessSigBytes,
		msg,
		nil,
		publicKey,
		publicKey,
		nil,
		false,
	)
	if !status || err != nil {
		return errors.Wrap(err, "AggsigVerifySingle failed")
	}

	return nil
}

// Offset is a part of blinding factors sum, sometimes referred to as K1, that is
// R*G = (K1+K2)*G. K1 is visible as offset field, K2 is published as commitment, i.e. K2*G = kernel_excess.
// if transaction is valid, then
// offset*G + kernel_excess === 0*H + R*G === (inputs - outputs - fee))*G === inputs*G - (outputs+Fee)*G ===
// === InputCommitmentsSum - (OutputCommitments + FeeCommitments)
func validateCommitmentsSum(context *secp256k1.Context, tx *core.Transaction) error {
	// parse inputs and outputs

	var outputs, inputs []*secp256k1.Commitment

	for i, input := range tx.Body.Inputs {
		commitmentBytes, err := hex.DecodeString(input.Commit)
		if err != nil {
			return errors.Wrapf(err, "cannot decode input.Commit from hex for input %v", i)
		}

		status, commitment, err := secp256k1.CommitmentParse(context, commitmentBytes)
		if !status || err != nil {
			return errors.Wrapf(err, "cannot parse commitmentBytes for input %v", i)
		}

		inputs = append(inputs, commitment)
	}

	for i, output := range tx.Body.Outputs {
		commitmentBytes, err := hex.DecodeString(output.Commit)
		if err != nil {
			return errors.Wrapf(err, "cannot decode input.Commit from hex for output %v", i)
		}

		status, commitment, err := secp256k1.CommitmentParse(context, commitmentBytes)
		if !status || err != nil {
			return errors.Wrapf(err, "cannot parse commitmentBytes for output %v", i)
		}

		outputs = append(outputs, commitment)
	}

	// verify kernel sums

	var zeroBlindingFactor [32]byte

	// NB: FEE = Overage (grin core terminology)
	overage := uint64(tx.Body.Kernels[0].Fee)

	status, overageCommitment, err := secp256k1.Commit(context, zeroBlindingFactor, overage, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if !status || err != nil {
		return errors.Wrap(err, "cannot calculate overageCommitment")
	}

	// the first part of equality to check
	// InputCommitmentsSum - (OutputCommitments + FeeCommitments)
	status, commitmentsSum, err := secp256k1.CommitSum(context, inputs, append(outputs, overageCommitment))
	if !status || err != nil {
		return errors.Wrap(err, "cannot calculate commitmentsSum")
	}

	// serialize it to simplify equality check
	status, serializedCommitmentsSum, err := secp256k1.CommitmentSerialize(context, commitmentsSum)
	if !status || err != nil {
		return errors.Wrap(err, "cannot serialize commitmentsSum")
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

	var offset32 [32]byte

	copy(offset32[:], offsetBytes[:32])

	status, offsetCommitment, err := secp256k1.Commit(context, offset32, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if !status || err != nil {
		return errors.Wrap(err, "cannot calculate offsetCommitment")
	}

	status, excessCommitment, err := secp256k1.CommitmentParse(context, excessBytes)
	if !status || err != nil {
		return errors.Wrap(err, "cannot parse excessBytes")
	}

	status, kernelExcess, err := secp256k1.CommitSum(context, make([]*secp256k1.Commitment, 0), (&([2]*secp256k1.Commitment{offsetCommitment, excessCommitment}))[:])
	if !status || err != nil {
		return errors.Wrap(err, "cannot calculate kernelExcess")
	}

	status, serializedKernelExcess, err := secp256k1.CommitmentSerialize(context, kernelExcess)
	if !status || err != nil {
		return errors.Wrap(err, "cannot serialize kernelExcess")
	}

	if bytes.Compare(serializedKernelExcess[:], serializedCommitmentsSum[:]) != 0 {
		return errors.New("serializedKernelExcess not equal to serializedCommitmentsSum")
	}

	return nil
}

func validateBulletproofs(context *secp256k1.Context, tx *core.Transaction) error {
	scratch, err := secp256k1.ScratchSpaceCreate(context, 1024*1024)
	if err != nil {
		return errors.Wrap(err, "cannot ScratchSpaceCreate")
	}

	bulletproofGenerators := secp256k1.BulletproofGeneratorsCreate(context, &secp256k1.GeneratorG, 256)
	if bulletproofGenerators == nil {
		return errors.Wrap(err, "cannot BulletproofGeneratorsCreate")
	}

	for i, output := range tx.Body.Outputs {
		err := validateBulletproof(context, output, scratch, bulletproofGenerators)
		if err != nil {
			return errors.Wrapf(err, "cannot validateBulletproof output %v", i)
		}
	}

	return nil
}

func validateBulletproof(context *secp256k1.Context, output core.Output, scratch *secp256k1.ScratchSpace, bulletproofGenerators *secp256k1.BulletproofGenerators) error {
	commitmentBytes, err := hex.DecodeString(output.Commit)
	if err != nil {
		return errors.Wrap(err, "cannot decode Commit from hex")
	}

	status, BPCommitment, err := secp256k1.CommitmentParse(context, commitmentBytes)
	if !status || err != nil {
		return errors.Wrap(err, "cannot parse commitmentBytes")
	}

	proofBytes, err := hex.DecodeString(output.Proof)
	if err != nil {
		return errors.Wrap(err, "cannot decode Proof from hex")
	}

	proofStatus, err := secp256k1.BulletproofRangeproofVerify(
		context,
		scratch,
		bulletproofGenerators,
		proofBytes,
		nil, // min_values: NULL for all-zeroes minimum values to prove ranges above
		BPCommitment,
		64,
		&secp256k1.GeneratorH,
		nil)
	if proofStatus != 1 || err != nil {
		return errors.Wrap(err, "cannot BulletproofRangeproofVerify")
	}

	return nil
}
