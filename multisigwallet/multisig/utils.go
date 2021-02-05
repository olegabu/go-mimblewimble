package multisig

import (
	"encoding/hex"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/multisigwallet/types"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func commitsFromBlinds(context *secp256k1.Context, blinds ...[]byte) (commits []*secp256k1.Commitment, err error) {
	for _, blind := range blinds {
		commit, e := secp256k1.Commit(context, blind, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
		if e != nil {
			err = errors.Wrap(e, "cannot create commit from blind")
			return
		}
		commits = append(commits, commit)
	}
	return
}

// blind + v * assetBlind
func computeBlindValueAssetBlind(wallet Wallet, output SavedOutput) (blindValueAssetBlind [32]byte, err error) {
	var blind [32]byte
	if output.PartialBlind != nil {
		blind = *output.PartialBlind
	} else {
		blind, err = wallet.Secret(output.Index)
		if err != nil {
			err = errors.Wrap(err, "cannot get blind by index")
			return
		}
	}

	var assetBlind [32]byte
	if output.PartialBlind != nil {
		assetBlind = *output.PartialAssetBlind
	} else {
		assetBlind, err = wallet.Secret(output.AssetIndex)
		if err != nil {
			err = errors.Wrap(err, "cannot get blind by index")
			return
		}
	}

	blindValueAssetBlind, err = secp256k1.BlindValueGeneratorBlindSum(output.Value, assetBlind[:], blind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}
	return
}

func findCorrespondingParticipantData(slates []*Slate, participantID string) (slate *ParticipantData, err error) {
	for _, slate := range slates {
		if slate.ParticipantData[participantID].PartSig != nil {
			return slate.ParticipantData[participantID], nil
		}
	}
	return nil, errors.New("cannot find partial signature")
}

func aggregateBulletproofMPCValues(context *secp256k1.Context, slate *Slate) (
	sumPublicTau1 *secp256k1.PublicKey,
	sumPublicTau2 *secp256k1.PublicKey,
	sumTaux [32]byte,
	commonNonce []byte,
	err error,
) {
	publicTau1s := make([]*secp256k1.PublicKey, 0)
	publicTau2s := make([]*secp256k1.PublicKey, 0)
	tauxs := make([][]byte, 0)
	commonNonce = make([]byte, 32)
	for _, participantData := range slate.ParticipantData {
		if !participantData.IsMultisigFundOwner {
			continue
		}

		// TODO: Check it
		publicNonceBytes, e := hex.DecodeString(participantData.PublicNonce)
		if e != nil {
			err = errors.Wrap(e, "cannot DecodeString")
			return
		}

		for i := 0; i < 32; i++ {
			commonNonce[i] = commonNonce[i] ^ publicNonceBytes[i+1]
		}

		publicTau1Bytes, e := hex.DecodeString(participantData.BulletproofsShare.PublicTau1)
		if e != nil {
			err = errors.Wrap(e, "cannot decode PublicTau1")
			return
		}

		_, publicTau1, e := secp256k1.EcPubkeyParse(context, publicTau1Bytes)
		if e != nil {
			err = errors.Wrap(e, "cannot parse PublicTau1")
			return
		}
		publicTau1s = append(publicTau1s, publicTau1)

		publicTau2Bytes, e := hex.DecodeString(participantData.BulletproofsShare.PublicTau2)
		if e != nil {
			err = errors.Wrap(e, "cannot decode PublicTau2")
			return
		}

		_, publicTau2, e := secp256k1.EcPubkeyParse(context, publicTau2Bytes)
		if e != nil {
			err = errors.Wrap(e, "cannot parse PublicTau2")
			return
		}
		publicTau2s = append(publicTau2s, publicTau2)

		if participantData.BulletproofsShare.Taux != "" {
			taux, e := hex.DecodeString(participantData.BulletproofsShare.Taux)
			if e != nil {
				err = errors.Wrap(e, "cannot decode Taux")
				return
			}
			tauxs = append(tauxs, taux)
		}
	}

	_, sumPublicTau1, err = secp256k1.EcPubkeyCombine(context, publicTau1s)
	if err != nil {
		err = errors.Wrap(err, "cannot combine PublicTau1s")
		return
	}

	_, sumPublicTau2, err = secp256k1.EcPubkeyCombine(context, publicTau2s)
	if err != nil {
		err = errors.Wrap(err, "cannot combine PublicTau2s")
		return
	}

	if len(tauxs) > 0 {
		sumTaux, err = secp256k1.BlindSum(context, tauxs, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot sum tauxs")
			return
		}
	}
	return
}

//  Surjection proof proves that for a particular output there is at least one corresponding input with the same asset id.
//	The sender must create both change outputs and outputs which she wishes to acquire as a result of this transaction,
//	because she must generate blinding factors for them to be available for later spending.
func addSurjectionProof(context *secp256k1.Context, output *SlateOutput, inputs []SlateInput, asset string /*, outputAsset string, inputAsset string*/) (err error) {
	var fixedInputTags []*secp256k1.FixedAssetTag
	var inputAssetBlinds [][]byte
	var fixedOutputTag *secp256k1.FixedAssetTag
	var ephemeralInputTags []*secp256k1.Generator
	var ephemeralOutputTag *secp256k1.Generator

	fixedOutputTag, err = secp256k1.FixedAssetTagFromHex(output.AssetTag)

	ephemeralOutputTag, err = secp256k1.GeneratorFromString(output.AssetCommit)
	if err != nil {
		return
	}

	for _, input := range inputs {
		var assetTag *secp256k1.FixedAssetTag
		var assetGenerator *secp256k1.Generator

		assetGenerator, e := secp256k1.GeneratorFromString(input.AssetCommit)
		if e != nil {
			err = errors.Wrap(e, "cannot get assetGenerator")
			return
		}

		assetTag, e = secp256k1.FixedAssetTagFromHex(input.AssetTag)

		if e != nil {
			err = errors.Wrap(e, "cannot get assetTag")
			return
		}

		fixedInputTags = append(fixedInputTags, assetTag)
		assetBlind, e := hex.DecodeString(input.AssetBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot get assetBlind")
			return
		}

		ephemeralInputTags = append(ephemeralInputTags, assetGenerator)
		inputAssetBlinds = append(inputAssetBlinds, assetBlind)
	}

	outputAssetBlind, err := hex.DecodeString(output.AssetBlind)
	if err != nil {
		return
	}

	seed32 := secp256k1.Random256()

	inputTagsToUse := len(inputs)
	maxIterations := 100

	_, proof, inputIndex, err := secp256k1.SurjectionproofInitialize(
		context,
		fixedInputTags,
		inputTagsToUse,
		fixedOutputTag,
		maxIterations,
		seed32[:])

	if inputTagsToUse < inputIndex {
		return errors.New("input not found")
	}

	err = secp256k1.SurjectionproofGenerate(
		context,
		proof,
		ephemeralInputTags[:],
		ephemeralOutputTag,
		inputIndex,
		inputAssetBlinds[inputIndex][:],
		outputAssetBlind[:])
	if err != nil {
		return
	}

	output.AssetProof = proof.String()

	return nil
}

func newOutput(
	wallet Wallet,
	value uint64,
	features ledger.OutputFeatures,
	asset string,
	status OutputStatus,
) (
	walletOutput *SavedOutput,
	sumBlinds []byte,
	err error,
) {
	secret, blindIndex, err := wallet.NewSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}
	blind := secret

	assetSecret, assetIndex, err := wallet.NewSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}
	assetBlind := assetSecret

	sumBlinds32, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind[:], blind[:])
	if e != nil {
		err = errors.Wrap(e, "cannot calculate sumBlinds32")
	}
	sumBlinds = sumBlinds32[:]

	seed := ledger.AssetSeed(asset)
	assetTag, err := secp256k1.FixedAssetTagParse(seed)
	if err != nil {
		err = errors.Wrap(err, "cannot get assetTag")
		return
	}

	assetCommitment, err := secp256k1.GeneratorGenerateBlinded(wallet.GetContext(), assetTag.Slice(), assetBlind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to asset")
		return
	}

	// create commitment to value with asset specific generator
	commitment, err := secp256k1.Commit(
		wallet.GetContext(),
		blind[:],
		value,
		assetCommitment,
		&secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to value")
		return
	}

	// create range proof to value with blinded H: assetCommitment
	proof, err := secp256k1.BulletproofRangeproofProveSingleCustomGen(
		wallet.GetContext(),
		nil,
		nil,
		value,
		blind[:],
		blind[:],
		nil,
		nil,
		nil,
		assetCommitment)
	if err != nil {
		err = errors.Wrap(err, "cannot create bulletproof")
		return
	}

	walletOutput = &SavedOutput{
		SlateOutput: SlateOutput{
			Output: ledger.Output{
				Input: ledger.Input{
					Features:    features,
					Commit:      commitment.String(),
					AssetCommit: assetCommitment.String(),
				},
				Proof: hex.EncodeToString(proof),
			},
			AssetTag:   assetTag.Hex(),
			AssetBlind: hex.EncodeToString(assetBlind[:]),
		},
		Value:      value,
		Index:      blindIndex,
		AssetIndex: assetIndex,
		Asset:      asset,
		Status:     status,
	}

	return
}
