package ledger

import (
	"encoding/hex"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func PersistTransaction(tx *Transaction, db Database) error {
	// check if inputs exist and mark them spent
	for i, input := range tx.Body.Inputs {
		err := db.InputExists(input)
		if err != nil {
			return errors.Wrapf(err, "input does not exist: %v at position %v", input.Commit, i)
		}

		err = db.SpendInput(input)
		if err != nil {
			return errors.Wrapf(err, "cannot mark input as spent: %v at position %v", input.Commit, i)
		}
	}

	// save new outputs
	for i, output := range tx.Body.Outputs {
		err := db.PutOutput(output)
		if err != nil {
			return errors.Wrapf(err, "cannot save output: %v at position %v", output.Commit, i)
		}
	}

	if len(tx.Body.Kernels) != 1 {
		return errors.New("expected one kernel in transaction")
	}

	// reconstitute full kernel from tx kernel and offset and save it
	kernel := tx.Body.Kernels[0]

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	excess, err := secp256k1.CommitmentFromString(kernel.Excess)
	if err != nil {
		return errors.Wrap(err, "cannot CommitmentFromString")
	}

	offsetBytes, _ := hex.DecodeString(tx.Offset)
	kernelOffset, err := secp256k1.Commit(context, offsetBytes, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return errors.Wrap(err, "cannot Commit")
	}

	fullExcess, err := secp256k1.CommitSum(context, []*secp256k1.Commitment{excess, kernelOffset}, []*secp256k1.Commitment{})
	if err != nil {
		return errors.Wrap(err, "cannot CommitSum")
	}

	kernel.Excess = fullExcess.String()

	err = db.PutKernel(kernel)
	if err != nil {
		return errors.Wrapf(err, "cannot save kernel: %v", kernel)
	}

	return nil
}
func PersistIssue(issue *Issue, db Database) error {
	// save new output
	err := db.PutOutput(issue.Output)
	if err != nil {
		return errors.Wrapf(err, "cannot save issue output: %v", issue.Output.Commit)
	}

	// save kernel
	err = db.PutKernel(issue.Kernel)
	if err != nil {
		return errors.Wrapf(err, "cannot save issue kernel: %v", issue.Kernel)
	}

	// save asset
	db.AddAsset(issue.Asset, issue.Value)

	return nil
}
