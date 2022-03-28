package ledger

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
)

func PersistTransaction(tx *Transaction, db Database, doublespend bool) error {
	// check if inputs exist and mark them spent
	for i, input := range tx.Body.Inputs {
		err := db.InputExists(input)
		if err != nil {
			return fmt.Errorf("%w: input does not exist: %v at position %v", err, input.Commit, i)
		}

		if !doublespend {
			err = db.SpendInput(input)
			if err != nil {
				return fmt.Errorf("%w: cannot mark input as spent: %v at position %v", err, input.Commit, i)
			}
		}
	}

	// save new outputs
	for i, output := range tx.Body.Outputs {
		err := db.PutOutput(output)
		if err != nil {
			return fmt.Errorf("%w: cannot save output: %v at position %v", err, output.Commit, i)
		}
	}

	if len(tx.Body.Kernels) != 1 {
		return errors.New("expected one kernel in transaction")
	}

	// reconstitute full kernel from tx kernel and offset and save it
	kernel := tx.Body.Kernels[0]

	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return fmt.Errorf("%w: cannot ContextCreate", err)
	}

	defer secp256k1.ContextDestroy(context)

	excess, err := secp256k1.CommitmentFromString(kernel.Excess)
	if err != nil {
		return fmt.Errorf("%w: cannot CommitmentFromString", err)
	}

	offsetBytes, _ := hex.DecodeString(tx.Offset)
	kernelOffset, err := secp256k1.Commit(context, offsetBytes, 0, &secp256k1.GeneratorH)
	if err != nil {
		return fmt.Errorf("%w: cannot Commit", err)
	}

	fullExcess, err := secp256k1.CommitSum(context, []*secp256k1.Commitment{excess, kernelOffset}, []*secp256k1.Commitment{})
	if err != nil {
		return fmt.Errorf("%w: cannot CommitSum", err)
	}

	kernel.Excess = secp256k1.CommitmentString(fullExcess)

	err = db.PutKernel(kernel)
	if err != nil {
		return fmt.Errorf("%w: cannot save kernel: %v", err, kernel)
	}

	return nil
}
func PersistIssue(issue *Issue, db Database) error {
	// save new output
	err := db.PutOutput(issue.Output)
	if err != nil {
		return fmt.Errorf("%w: cannot save issue output: %v", err, issue.Output.Commit)
	}

	// save kernel
	err = db.PutKernel(issue.Kernel)
	if err != nil {
		return fmt.Errorf("%w: cannot save issue kernel: %v", err, issue.Kernel)
	}

	// save asset
	db.AddAsset(issue.Asset, issue.Value)

	return nil
}
