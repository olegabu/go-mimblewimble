package ledger

import (
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

	return nil
}
