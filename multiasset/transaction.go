package multiasset

import (
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/olegabu/go-secp256k1-zkp"
)

type Transaction struct {
	Offset string `json:"offset"`
	// The transaction body - inputs/outputs/kernels
	Body TransactionBody `json:"body"`
	ID   uuid.UUID       `json:"id,omitempty"`
}

type TransactionBlinded struct {
	Offset string `json:"offset"`
	// The transaction body - inputs/outputs/kernels
	Body TransactionBodyBlinded `json:"body"`
	ID   uuid.UUID              `json:"id,omitempty"`
}

type TransactionBodyBlinded struct {
	Inputs  []Input        `json:"inputs"`
	Outputs []PublicOutput `json:"outputs"`
	Kernels []TxKernel     `json:"kernels"`
}

type TransactionBody struct {
	Inputs  []SlateInput  `json:"inputs"`
	Outputs []SlateOutput `json:"outputs"`
	Kernels []TxKernel    `json:"kernels"`
}

func (t *TransactionBlinded) validateTokenCommitments(ctx *secp256k1.Context) error {
	for _, output := range t.Body.Outputs {
		if err := validateSurjectionProof(ctx, output, t.Body.Inputs); err != nil {
			return err
		}
	}
	return nil
}
func validateSurjectionProof(ctx *secp256k1.Context, output PublicOutput, inputs []Input) (err error) {

	var outputAssetCommitmentBytes []byte
	outputAssetCommitmentBytes, err = hex.DecodeString(output.Commit.AssetCommitment)
	if err != nil {
		return
	}
	ephemeralOutputTag, err := secp256k1.GeneratorParse(ctx, outputAssetCommitmentBytes)
	if err != nil {
		return
	}

	var ephemeralInputTags []secp256k1.Generator
	for _, input := range inputs {
		var ephemeralInputTag *secp256k1.Generator
		var inputAssetCommitmentBytes []byte
		inputAssetCommitmentBytes, err = hex.DecodeString(input.Commit.AssetCommitment)
		ephemeralInputTag, err = secp256k1.GeneratorParse(ctx, inputAssetCommitmentBytes)
		if err != nil {
			return
		}
		ephemeralInputTags = append(ephemeralInputTags, *ephemeralInputTag)
	}

	proof, err := secp256k1.SurjectionproofParse(ctx, []byte(output.SurjectionProof))

	err = secp256k1.SurjectionproofVerify(ctx, &proof, ephemeralInputTags, *ephemeralOutputTag)

	return

}
