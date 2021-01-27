package multisigwallet

import (
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) InitMultipartyTransaction(
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

func (t *Wallet) SignMultipartyTransaction(
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

	assetBlind, err := t.secret(savedSlate.AssetBlindIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot DecodeString")
		return
	}

	blind, err := t.secret(savedSlate.BlindIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot get blind")
		return
	}

	taux, err := t.computeTaux(blind[:], assetBlind[:], slate)
	if err != nil {
		err = errors.Wrap(err, "cannot computeTaux")
		return
	}
	slate.ParticipantData[participantID].BulletproofsShare.Taux = hex.EncodeToString(taux)

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) AggregateMultipartyTransaction(
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

	output, err := t.createMultipartyOutput(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot createMultipartyOutput")
		return
	}
	slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, *output)

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

	multipartyOutput = &SavedOutput{
		SlateOutput: *output,
		Value:       uint64(slate.Amount),
		Index:       savedSlate.BlindIndex,
		Asset:       slate.Asset,
		AssetIndex:  savedSlate.AssetBlindIndex,
		Status:      OutputUnconfirmed,
	}

	return
}
