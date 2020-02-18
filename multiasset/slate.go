package multiasset

import (
	"encoding/hex"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (slate *Slate) generateSurjectionProof(context *secp256k1.Context, inputs []SlateOutput, output SlateOutput) (proof *secp256k1.Surjectionproof, err error) {
	/*
		The surjection proof proves that for a particular output there is at least one corresponding input with the same asset id.
		The sender must create both change outputs and outputs which she wishes to acquire as a result of this transaction,
		because she must generate blinding factors for them to be available for later spending.
	*/
	var fixedInputAssetTags []secp256k1.FixedAssetTag

	var inputIndex int
	var inputBlindingKeys [][]byte
	asset := output.Asset
	var fixedOutputAssetTag *secp256k1.FixedAssetTag
	var ephemeralInputTags []secp256k1.Generator
	var ephemeralOutputTag *secp256k1.Generator

	fixedOutputAssetTag, err = secp256k1.FixedAssetTagParse(asset.seed())

	for _, input := range inputs {
		var fixedAssetTag *secp256k1.FixedAssetTag
		var tokenCommitment *secp256k1.Generator
		fixedAssetTag, err = secp256k1.FixedAssetTagParse(input.Asset.seed())

		if err != nil {
			return
		}
		fixedInputAssetTags = append(fixedInputAssetTags, *fixedAssetTag)

		var inputAssetBlind []byte
		inputAssetBlind, err = hex.DecodeString(input.AssetBlind)
		if err != nil {
			return
		}
		tokenCommitment, err = secp256k1.GeneratorGenerateBlinded(context, input.Asset.seed(), inputAssetBlind)
		if err != nil {
			return
		}
		ephemeralInputTags = append(ephemeralInputTags, *tokenCommitment)

		inputBlindingKeys = append(inputBlindingKeys, inputAssetBlind)
	}

	var outputAssetBlind []byte
	outputAssetBlind, err = hex.DecodeString(output.AssetBlind)
	ephemeralOutputTag, err = secp256k1.GeneratorGenerateBlinded(context, output.Asset.seed(), outputAssetBlind[:])

	if err != nil {
		return
	}

	seed32 := secp256k1.Random256()

	_, proof, inputIndex, err = secp256k1.SurjectionproofAllocateInitialized(context, fixedInputAssetTags, 1, fixedOutputAssetTag, 10, seed32[:])

	if len(inputBlindingKeys) < inputIndex {
		return nil, errors.Wrap(nil, "input not found")
	}
	err = secp256k1.SurjectionproofGenerate(context, proof, ephemeralInputTags[:], *ephemeralOutputTag, inputIndex, inputBlindingKeys[inputIndex][:], outputAssetBlind[:])
	if err != nil {
		return
	}

	return proof, nil

}
