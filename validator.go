package go_mimblewimble

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	libgrin "github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

func VerifySignature(txBytes []byte) error {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate ContextBoth")
	}

	tx := &libgrin.Transaction{}

	err = json.Unmarshal(txBytes, tx)
	if err != nil {
		return errors.Wrap(err, "cannot unmarshal json to Transaction")
	}

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

	// _, serPubkey, _ := secp256k1.EcPubkeySerialize(context, pubkey)
	fmt.Printf("fee : %v\nfeatures: %v\nmsg:%v\nexcessBytes:%v\n", fee, features, hex.EncodeToString(msg), hex.EncodeToString(excessBytes))

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
func VerifyCommitmentsSum(txBytes []byte) error {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate ContextBoth")
	}

	tx := &libgrin.Transaction{}

	err = json.Unmarshal(txBytes, tx)
	if err != nil {
		return errors.Wrap(err, "cannot unmarshal json to Transaction")
	}

	// parse inputs and outputs

	var outputs, inputs []*secp256k1.Commitment

	for _, input := range tx.Body.Inputs {
		commitmentBytes, err := hex.DecodeString(input.Commit)
		if err != nil {
			return errors.Wrap(err, "cannot decode input.Commit from hex")
		}

		status, commitment, err := secp256k1.CommitmentParse(context, commitmentBytes)
		if !status || err != nil {
			return errors.Wrap(err, "cannot parse commitmentBytes")
		}

		inputs = append(inputs, commitment)
	}

	for _, output := range tx.Body.Outputs {
		commitmentBytes, err := hex.DecodeString(output.Commit)
		if err != nil {
			return errors.Wrap(err, "cannot decode output.Commit from hex")
		}

		status, commitment, err := secp256k1.CommitmentParse(context, commitmentBytes)
		if !status || err != nil {
			return errors.Wrap(err, "cannot parse commitmentBytes")
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
