package multisigwallet

import (
	"encoding/hex"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) preparePartyData(inputs []SavedOutput, change uint64) (
	blind [32]byte,
	blindIndex uint32,
	assetBlind [32]byte,
	assetBlindIndex uint32,
	offset [32]byte,
	blindExcess [32]byte,
	nonce [32]byte,
	changeOutput *SavedOutput,
	err error,
) {
	// generate partial output blind
	blind, blindIndex, err = t.newSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}

	// generate partial output asset blind
	assetBlind, assetBlindIndex, err = t.newSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}

	// generate random offset
	offset, err = t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for offset")
		return
	}

	// generate secret nonce
	nonce, err = t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	// create change output and remember its blinding factor
	if change > 0 {
		changeOutput, _, err = t.newOutput(change, ledger.PlainOutput, inputs[0].Asset, OutputUnconfirmed)
		if err != nil {
			err = errors.Wrap(err, "cannot create change output")
			return
		}
	}

	// compute excess blinding factor
	inputsBlindValueAssetBlinds := make([][]byte, 0)
	for _, input := range inputs {
		blindValueAssetBlind, e := t.getBlindValueAssetBlind(input)
		if e != nil {
			err = errors.Wrap(e, "cannot getBlindValueAssetBlind")
			return
		}
		inputsBlindValueAssetBlinds = append(inputsBlindValueAssetBlinds, blindValueAssetBlind[:])
	}

	changeBlindValueAssetBlinds, err := t.getBlindValueAssetBlind(*changeOutput)
	if err != nil {
		err = errors.Wrap(err, "cannot getBlindValueAssetBlind")
		return
	}

	// x = change - inputs - offset (now change = 0)
	blindExcess, err = secp256k1.BlindSum(t.context, [][]byte{changeBlindValueAssetBlinds[:]}, append(inputsBlindValueAssetBlinds, offset[:]))
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}
	return
}

func (t *Wallet) getSharedData(
	slate *Slate,
) (
	publicBlinds []*secp256k1.Commitment,
	publicBlindExcesses []*secp256k1.Commitment,
	publicNonces []*secp256k1.Commitment,
	publicValueAssetBlinds []*secp256k1.Commitment,
	err error,
) {
	for _, party := range slate.ParticipantData {
		publicBlind, e := secp256k1.CommitmentFromString(party.PublicBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentFromString")
			return
		}
		publicBlinds = append(publicBlinds, publicBlind)

		publicBlindExcess, e := secp256k1.CommitmentFromString(party.PublicBlindExcess)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentFromString")
			return
		}
		publicBlindExcesses = append(publicBlindExcesses, publicBlindExcess)

		publicNonce, e := secp256k1.CommitmentFromString(party.PublicNonce)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentFromString")
			return
		}
		publicNonces = append(publicNonces, publicNonce)

		assetBlind, e := hex.DecodeString(party.AssetBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot DecodeString")
			return
		}

		valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(uint64(slate.Amount), assetBlind, new([32]byte)[:])
		if e != nil {
			err = errors.Wrap(e, "cannot BlindValueGeneratorBlindSum")
			return
		}

		publicValueAssetBlind, e := secp256k1.Commit(t.context, valueAssetBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
		if e != nil {
			err = errors.Wrap(e, "cannot Commit")
			return
		}
		publicValueAssetBlinds = append(publicValueAssetBlinds, publicValueAssetBlind)
	}
	return
}

func combinePartiallySignedSlates(slates []*Slate) (slate *Slate, err error) {
	slate = slates[0]
	for i, participantData := range slate.ParticipantData {
		correspondingParticipantData, err := findCorrespondingParticipantData(slates, participantData.PublicBlind)
		slate.ParticipantData[i].PartSig = correspondingParticipantData.PartSig
		slate.ParticipantData[i].BulletproofsShare.Taux = correspondingParticipantData.BulletproofsShare.Taux
		if err != nil {
			return nil, err
		}
	}
	return
}

func (t *Wallet) combineInitialSlates(slates []*Slate) (aggregatedSlate *Slate, err error) {
	// TODO: check slates

	inputs := make([]SlateInput, 0)
	outputs := make([]SlateOutput, 0)
	participantDatas := make([]ParticipantData, 0)
	var totalAmount ledger.Uint64
	var totalOffset [32]byte
	for i, slate := range slates {
		inputs = append(inputs, slate.Transaction.Body.Inputs...)
		outputs = append(outputs, slate.Transaction.Body.Outputs...)
		totalAmount += slate.Amount

		participantData := slate.ParticipantData[0]
		participantData.ID = ledger.Uint64(i)
		participantDatas = append(participantDatas, participantData)

		offset, err := hex.DecodeString(slate.Transaction.Offset)
		if err != nil {
			return nil, err
		}

		totalOffset, err = secp256k1.BlindSum(t.context, [][]byte{totalOffset[:], offset}, nil)
		if err != nil {
			return nil, err
		}
	}

	fee := slates[0].Transaction.Body.Kernels[0].Fee
	asset := slates[0].Asset
	id := slates[0].Transaction.ID

	aggregatedSlate = &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: uint(len(slates)),
		Transaction: SlateTransaction{
			ID:     id,
			Offset: hex.EncodeToString(totalOffset[:]),
			Body: SlateTransactionBody{
				Inputs:  inputs,
				Outputs: outputs,
				Kernels: []ledger.TxKernel{{
					Features:   ledger.PlainKernel,
					Fee:        fee,
					LockHeight: 0,
					Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
					ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				}},
			},
		},
		Amount:          totalAmount,
		Fee:             fee,
		Height:          0,
		LockHeight:      0,
		ParticipantData: participantDatas,
		Asset:           asset,
	}
	return
}

func (t *Wallet) computeMultipartyCommit(slate *Slate) (
	commit *secp256k1.Commitment,
	assetCommit *secp256k1.Generator,
	assetTag *secp256k1.FixedAssetTag,
	aggregatedAssetBlind [32]byte,
	err error,
) {
	publicBlinds, _, _, _, err := t.getSharedData(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot extractParticipantData")
		return
	}

	for _, party := range slate.ParticipantData {
		assetBlind, e := hex.DecodeString(party.AssetBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot DecodeString")
			return
		}

		// TODO: CHECK IT
		aggregatedAssetBlind, e = secp256k1.BlindSum(t.context, [][]byte{aggregatedAssetBlind[:], assetBlind}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot BlindSum")
			return
		}
	}

	assetTag, err = secp256k1.FixedAssetTagParse(ledger.AssetSeed(slate.Asset))
	if err != nil {
		err = errors.Wrap(err, "cannot get assetTag")
		return
	}

	assetCommit, err = secp256k1.GeneratorGenerateBlinded(t.context, assetTag.Slice(), aggregatedAssetBlind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to asset")
		return
	}

	commit, err = secp256k1.Commit(t.context, new([32]byte)[:], uint64(slate.Amount), assetCommit, &secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to value")
		return
	}

	commit, err = secp256k1.CommitSum(t.context, append(publicBlinds, commit), nil)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum")
		return
	}
	return
}

func (t *Wallet) createMultipartyOutput(slate *Slate) (output *SlateOutput, err error) {
	commit, assetCommit, assetTag, aggregatedAssetBlind, err := t.computeMultipartyCommit(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot computeMultipartyCommit")
		return
	}

	proof, err := t.aggregateProof(slate, commit, assetCommit)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregateProof")
		return
	}

	output = &SlateOutput{
		Output: ledger.Output{
			Input: ledger.Input{
				Features:    ledger.PlainOutput,
				Commit:      commit.String(),
				AssetCommit: assetCommit.String(),
			},
			Proof: hex.EncodeToString(proof),
		},
		AssetTag:   assetTag.Hex(),
		AssetBlind: hex.EncodeToString(aggregatedAssetBlind[:]),
	}
	return
}

func (t *Wallet) newOutput(
	value uint64,
	features ledger.OutputFeatures,
	asset string,
	status OutputStatus,
) (
	walletOutput *SavedOutput,
	sumBlinds []byte,
	err error,
) {
	secret, index, err := t.newSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}

	blind := secret[:]

	assetSecret, assetIndex, err := t.newSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}

	assetBlind := assetSecret[:]

	sumBlinds32, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind, blind)
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

	assetCommitment, err := secp256k1.GeneratorGenerateBlinded(t.context, assetTag.Slice(), assetBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to asset")
		return
	}

	// create commitment to value with asset specific generator
	commitment, err := secp256k1.Commit(
		t.context,
		blind,
		value,
		assetCommitment,
		&secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to value")
		return
	}

	// create range proof to value with blinded H: assetCommitment
	proof, err := secp256k1.BulletproofRangeproofProveSingleCustomGen(
		t.context,
		nil,
		nil,
		value,
		blind,
		blind,
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
			AssetBlind: hex.EncodeToString(assetBlind),
		},
		Value:      value,
		Index:      index,
		Asset:      asset,
		AssetIndex: assetIndex,
		Status:     status,
	}

	return
}

//  Surjection proof proves that for a particular output there is at least one corresponding input with the same asset id.
//	The sender must create both change outputs and outputs which she wishes to acquire as a result of this transaction,
//	because she must generate blinding factors for them to be available for later spending.
func (t *Wallet) addSurjectionProof(output *SlateOutput, inputs []SlateInput, asset string /*, outputAsset string, inputAsset string*/) (err error) {
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
		t.context,
		fixedInputTags,
		inputTagsToUse,
		fixedOutputTag,
		maxIterations,
		seed32[:])

	if inputTagsToUse < inputIndex {
		return errors.New("input not found")
	}

	err = secp256k1.SurjectionproofGenerate(
		t.context,
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
