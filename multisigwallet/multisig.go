package multisigwallet

import (
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) initMultipartyTransaction(
	inputs []SavedOutput,
	change uint64,
	fee uint64,
	id uuid.UUID,
) (
	slateBytes []byte,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	blind, blindIndex, assetBlind, assetBlindIndex, offset, blindExcess, nonce, changeOutput, err := t.preparePartyData(inputs, change)
	if err != nil {
		err = errors.Wrap(err, "cannot generatePartialData")
		return
	}

	commits, err := commitsFromBlinds(t.context, blind[:], blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot get commits from secrets")
		return
	}

	publicBlind := commits[0]
	publicBlindExcess := commits[1]
	publicNonce := commits[2]

	slateInputs := make([]SlateInput, 0)
	for _, input := range inputs {
		inputAssetBlind, e := t.secret(input.AssetIndex)
		if e != nil {
			err = errors.Wrap(e, "cannot get input's asset blind")
			return
		}

		slateInput := SlateInput{
			Input: ledger.Input{
				Features:    input.Features,
				Commit:      input.Commit,
				AssetCommit: input.AssetCommit,
			},
			AssetTag:     input.AssetTag,
			AssetBlind:   hex.EncodeToString(inputAssetBlind[:]),
			IsMultiparty: input.IsMultiparty,
		}
		slateInputs = append(slateInputs, slateInput)
	}

	slateOutputs := make([]SlateOutput, 0)
	if changeOutput != nil {
		slateOutputs = append(slateOutputs, changeOutput.SlateOutput)
	}

	bulletproofsShare, err := t.generatePublicTaus(blind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot generatePublicTaus")
		return
	}

	var totalAmount uint64
	for _, input := range inputs {
		totalAmount += input.Value
	}
	totalAmount -= change

	slate := &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 1,
		Transaction: SlateTransaction{
			ID:     id,
			Offset: hex.EncodeToString(offset[:]),
			Body: SlateTransactionBody{
				Inputs:  slateInputs,
				Outputs: slateOutputs,
				Kernels: []ledger.TxKernel{{
					Features:   ledger.PlainKernel,
					Fee:        ledger.Uint64(fee),
					LockHeight: 0,
					Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
					ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				}},
			},
		},
		Amount:     ledger.Uint64(totalAmount),
		Fee:        ledger.Uint64(fee),
		Height:     0,
		LockHeight: 0,
		ParticipantData: []ParticipantData{{
			ID:                0,
			Value:             ledger.Uint64(totalAmount),
			PublicBlind:       publicBlind.String(),
			AssetBlind:        hex.EncodeToString(assetBlind[:]),
			PublicBlindExcess: publicBlindExcess.String(),
			PublicNonce:       publicNonce.String(),
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
			BulletproofsShare: bulletproofsShare,
		}},
		Asset: inputs[0].Asset,
	}

	savedSlate = &SavedSlate{
		Slate:           *slate,
		Nonce:           nonce,
		BlindIndex:      blindIndex,
		AssetBlindIndex: assetBlindIndex,
		ExcessBlind:     blindExcess,
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	if changeOutput != nil {
		walletOutputs = []SavedOutput{*changeOutput}
	}
	return
}

func (t *Wallet) signMultipartyTransaction(
	slates []*Slate,
	savedSlate *SavedSlate,
) (
	slateBytes []byte,
	err error,
) {
	slate, err := t.combineInitialSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "cannot combineInitialSlates")
		return
	}

	var participantID int
	for i, participantData := range slate.ParticipantData {
		if participantData.PublicBlind == savedSlate.ParticipantData[0].PublicBlind {
			participantID = i
			break
		}
	}

	partialSignature, err := t.createPartialSignature(slate, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot createPartialSignature")
		return
	}
	slate.ParticipantData[participantID].PartSig = &partialSignature

	if slate.Amount > 0 {
		assetBlind, e := t.secret(savedSlate.AssetBlindIndex)
		if e != nil {
			err = errors.Wrap(e, "cannot DecodeString")
			return
		}

		blind, e := t.secret(savedSlate.BlindIndex)
		if e != nil {
			err = errors.Wrap(e, "cannot get blind")
			return
		}

		taux, e := t.computeTaux(blind[:], assetBlind[:], slate)
		if e != nil {
			err = errors.Wrap(e, "cannot computeTaux")
			return
		}
		slate.ParticipantData[participantID].BulletproofsShare.Taux = hex.EncodeToString(taux)
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) aggregateMultipartyTransaction(
	slates []*Slate,
	savedSlate *SavedSlate,
) (
	transactionBytes []byte,
	savedTransaction SavedTransaction,
	multipartyOutput *SavedOutput,
	err error,
) {
	slate, err := combinePartiallySignedSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "cannot combineSlates")
		return
	}

	var output *SlateOutput
	if slate.Amount > 0 {
		output, err = t.createMultipartyOutput(slate)
		if err != nil {
			err = errors.Wrap(err, "cannot createMultipartyOutput")
			return
		}
		slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, *output)
	}

	signature, err := t.aggregatePartialSignatures(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregatePartialSignatures")
		return
	}

	var inputCommitments, outputCommitments []*secp256k1.Commitment
	for _, input := range slate.Transaction.Body.Inputs {
		com, e := secp256k1.CommitmentFromString(input.Commit)
		if e != nil {
			err = errors.Wrap(e, "error parsing input commitment")
			return
		}
		inputCommitments = append(inputCommitments, com)
	}

	for _, output := range slate.Transaction.Body.Outputs {
		com, e := secp256k1.CommitmentFromString(output.Commit)
		if e != nil {
			err = errors.Wrap(e, "error parsing output commitment")
			return
		}
		outputCommitments = append(outputCommitments, com)
	}

	offsetBytes, err := hex.DecodeString(slate.Transaction.Offset)
	if err != nil {
		err = errors.Wrap(err, "cannot get offsetBytes")
		return
	}

	kernelExcess, err := ledger.CalculateExcess(t.context, inputCommitments, outputCommitments, offsetBytes, uint64(slate.Transaction.Body.Kernels[0].Fee))
	if err != nil {
		err = errors.Wrap(err, "cannot calculate kernel excess")
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(t.context, kernelExcess)
	if err != nil {
		err = errors.Wrap(err, "excessPublicKey: CommitmentToPublicKey failed")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// verify final sig with pk from excess
	err = secp256k1.AggsigVerifySingle(t.context, &signature, msg, nil, excessPublicKey, excessPublicKey, nil, false)
	if err != nil {
		err = errors.Wrap(err, "AggsigVerifySingle failed to verify the finalSig with excessPublicKey")
		return
	}
	excessSig := secp256k1.AggsigSignatureSerialize(t.context, &signature)

	transaction := ledger.Transaction{
		Offset: slate.Transaction.Offset,
		ID:     slate.Transaction.ID,
		Body: ledger.TransactionBody{
			Kernels: []ledger.TxKernel{
				{
					Excess:    kernelExcess.String(),
					ExcessSig: hex.EncodeToString(excessSig[:]),
				},
			},
		},
	}

	for _, o := range slate.Transaction.Body.Inputs {
		transaction.Body.Inputs = append(transaction.Body.Inputs, o.Input)
	}

	for _, o := range slate.Transaction.Body.Outputs {
		e := t.addSurjectionProof(&o, slate.Transaction.Body.Inputs, slate.Asset)
		if e != nil {
			err = errors.Wrap(e, "cannot addSurjectionProof")
			return
		}
		transaction.Body.Outputs = append(transaction.Body.Outputs, o.Output)
	}

	transactionBytes, err = json.Marshal(transaction)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal ledgerTx to json")
		return
	}

	savedTransaction = SavedTransaction{
		Transaction: transaction,
		Status:      TransactionUnconfirmed,
	}

	if slate.Amount > 0 {
		multipartyOutput = &SavedOutput{
			SlateOutput: *output,
			Value:       uint64(slate.Amount),
			Index:       savedSlate.BlindIndex,
			Asset:       slate.Asset,
			AssetIndex:  savedSlate.AssetBlindIndex,
			Status:      OutputUnconfirmed,
		}
	}

	return
}

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

	// compute excess blinding factor
	inputsBlindValueAssetBlinds := make([][]byte, 0)
	for _, input := range inputs {
		blindValueAssetBlind, e := t.computeBlindValueAssetBlind(input)
		if e != nil {
			err = errors.Wrap(e, "cannot getBlindValueAssetBlind")
			return
		}
		inputsBlindValueAssetBlinds = append(inputsBlindValueAssetBlinds, blindValueAssetBlind[:])
	}

	// x = change - inputs - offset (now change = 0)
	blindExcess, err = secp256k1.BlindSum(t.context, nil, append(inputsBlindValueAssetBlinds, offset[:]))
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}

	if change > 0 {
		// create change output and remember its blinding factor
		var e error
		changeOutput, _, e = t.newOutput(change, ledger.PlainOutput, inputs[0].Asset, OutputUnconfirmed)
		if e != nil {
			err = errors.Wrap(e, "cannot create change output")
			return
		}

		changeBlindValueAssetBlinds, e := t.computeBlindValueAssetBlind(*changeOutput)
		if e != nil {
			err = errors.Wrap(e, "cannot getBlindValueAssetBlind")
			return
		}

		blindExcess, e = secp256k1.BlindSum(t.context, [][]byte{blindExcess[:], changeBlindValueAssetBlinds[:]}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot BlindSum")
			return
		}
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

		if slate.Amount > 0 {
			publicBlind, e := secp256k1.CommitmentFromString(party.PublicBlind)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitmentFromString")
				return
			}
			publicBlinds = append(publicBlinds, publicBlind)

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
	}
	return
}

// TODO: refactoring
func (t *Wallet) combineInitialSlates(slates []*Slate) (aggregatedSlate *Slate, err error) {
	// TODO: check slates

	inputs := make([]SlateInput, 0)
	outputs := make([]SlateOutput, 0)
	participantDatas := make([]ParticipantData, 0)
	var totalAmount ledger.Uint64
	var totalOffset [32]byte
	for i, slate := range slates {
		for _, input := range slate.Transaction.Body.Inputs {
			if !input.IsMultiparty {
				inputs = append(inputs, input)
			}
		}
		outputs = append(outputs, slate.Transaction.Body.Outputs...)

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
		totalAmount += slate.Amount
	}

	savedOutput, getOutputErr := t.db.GetOutput(slates[0].Transaction.Body.Inputs[0].Commit)
	if getOutputErr == nil && savedOutput.IsMultiparty {
		multipartyInput := slates[0].Transaction.Body.Inputs[0]
		totalAmount = slates[0].Amount
		for i := 1; i < len(slates); i++ {
			multipartyAssetBlind, e := hex.DecodeString(multipartyInput.AssetBlind)
			if e != nil {
				err = errors.Wrap(e, "cannot DecodeString")
				return
			}

			currentAssetBlind, e := hex.DecodeString(slates[i].Transaction.Body.Inputs[0].AssetBlind)
			if e != nil {
				err = errors.Wrap(e, "cannot DecodeString")
				return
			}

			sumAssetBlind, e := secp256k1.BlindSum(t.context, [][]byte{multipartyAssetBlind, currentAssetBlind}, nil)
			if e != nil {
				err = errors.Wrap(e, "cannot BlindSum")
				return
			}
			multipartyInput.AssetBlind = hex.EncodeToString(sumAssetBlind[:])

			totalAmount -= ledger.Uint64(savedOutput.Value) - slates[i].Amount
		}
		inputs = append(inputs, multipartyInput)
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
		AssetTag:     assetTag.Hex(),
		AssetBlind:   hex.EncodeToString(aggregatedAssetBlind[:]),
		IsMultiparty: true,
	}
	return
}
