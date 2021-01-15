package multisigwallet

import (
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) InitMultipartyFundingTransaction(input *SavedOutput, fee uint64) (slateBytes []byte, savedSlate *SavedSlate, err error) {
	blind, assetBlind, offset, blindExcess, nonce, err := t.generatePartialData(input)
	if err != nil {
		err = errors.Wrap(err, "cannot generatePartialData")
		return
	}

	commits, err := t.commitsFromSecrets(blind[:], blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot get commits from secrets")
		return
	}

	publicBlind := commits[0]
	publicBlindExcess := commits[1]
	publicNonce := commits[2]

	inputAssetBlind, err := t.secret(input.AssetIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot get input's asset blind")
	}

	slateInput := SlateInput{
		Input: ledger.Input{
			Features:    input.Features,
			Commit:      input.Commit,
			AssetCommit: input.AssetCommit,
		},
		AssetTag:   input.AssetTag,
		AssetBlind: hex.EncodeToString(inputAssetBlind[:]),
	}

	slate := &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 1,
		Transaction: SlateTransaction{
			ID:     uuid.New(),
			Offset: hex.EncodeToString(offset[:]),
			Body: SlateTransactionBody{
				Inputs:  []SlateInput{slateInput},
				Outputs: nil,
				Kernels: []ledger.TxKernel{{
					Features:   ledger.PlainKernel,
					Fee:        ledger.Uint64(fee),
					LockHeight: 0,
					Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
					ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				}},
			},
		},
		Amount:     ledger.Uint64(input.Value),
		Fee:        ledger.Uint64(fee),
		Height:     0,
		LockHeight: 0,
		ParticipantData: []ParticipantData{{
			ID:                0,
			Value:             ledger.Uint64(input.Value),
			PublicBlind:       publicBlind.String(),
			AssetBlind:        hex.EncodeToString(assetBlind[:]),
			PublicBlindExcess: publicBlindExcess.String(),
			PublicNonce:       publicNonce.String(),
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
		}},
		Asset: input.Asset,
		//ReceiveAmount: ledger.Uint64(receiveAmount),
		//ReceiveAsset:  receiveAsset,
	}

	savedSlate = &SavedSlate{
		Slate:         *slate,
		Nonce:         nonce,
		Blind:         blind,
		ExcessBlind:   blindExcess,
		ParticipantID: 0,
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) ContributeMultipartyFundingTransaction(input *SavedOutput, slate *Slate) (slateBytes []byte, savedSlate *SavedSlate, err error) {
	blind, assetBlind, offset, blindExcess, nonce, err := t.generatePartialData(input)
	if err != nil {
		err = errors.Wrap(err, "cannot generatePartialData")
		return
	}

	commits, err := t.commitsFromSecrets(blind[:], blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot get commits from secrets")
		return
	}

	publicBlind := commits[0]
	publicBlindExcess := commits[1]
	publicNonce := commits[2]

	inputAssetBlind, err := t.secret(input.AssetIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot get input's asset blind")
	}

	slateInput := SlateInput{
		Input: ledger.Input{
			Features:    input.Features,
			Commit:      input.Commit,
			AssetCommit: input.AssetCommit,
		},
		AssetTag:   input.AssetTag,
		AssetBlind: hex.EncodeToString(inputAssetBlind[:]),
	}

	slate.NumParticipants++
	slate.Amount += ledger.Uint64(input.Value)
	slate.Transaction.Body.Inputs = append(slate.Transaction.Body.Inputs, slateInput)
	slate.ParticipantData = append(slate.ParticipantData, ParticipantData{
		ID:                ledger.Uint64(len(slate.ParticipantData)),
		Value:             ledger.Uint64(input.Value),
		PublicBlind:       publicBlind.String(),
		AssetBlind:        hex.EncodeToString(assetBlind[:]),
		PublicBlindExcess: publicBlindExcess.String(),
		PublicNonce:       publicNonce.String(),
		PartSig:           nil,
		Message:           nil,
		MessageSig:        nil,
	})

	// adding partial offset to accumulated offset
	accumulatedOffset, err := hex.DecodeString(slate.Transaction.Offset)
	if err != nil {
		err = errors.Wrap(err, "cannot Decode transaction offset")
		return
	}

	totalOffset, err := secp256k1.BlindSum(t.context, [][]byte{accumulatedOffset, offset[:]}, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}
	slate.Transaction.Offset = hex.EncodeToString(totalOffset[:])

	savedSlate = &SavedSlate{
		Slate:         *slate,
		Nonce:         nonce,
		Blind:         blind,
		ExcessBlind:   blindExcess,
		ParticipantID: ledger.Uint64(len(slate.ParticipantData)) - 1,
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) SignMultipartyFundingTransaction(slate *Slate, savedSlate *SavedSlate) (slateBytes []byte, err error) {
	publicBlinds, publicBlindExcesses, publicNonces, publicValueAssetBlinds, err := t.extractParticipantData(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot extractParticipantData")
		return
	}

	// Вычисление aggregated public key (Pagg)
	aggregatedPublicKey, err := t.computeAggregatedPublicKey(publicBlinds, publicValueAssetBlinds, publicBlindExcesses)
	if err != nil {
		err = errors.Wrap(err, "cannot computeAggregatedPublicKey")
		return
	}

	// Вычисление public nonce (Ragg)
	aggregatedPublicNonce, err := t.computeAggregatedNonce(publicNonces)
	if err != nil {
		err = errors.Wrap(err, "cannot computeAggregatedNonce")
		return
	}

	// Вычисление e
	msg := ledger.KernelSignatureMessage(savedSlate.Transaction.Body.Kernels[0])

	// Вычисление частичной подписи
	assetBlind, err := hex.DecodeString(slate.ParticipantData[savedSlate.ParticipantID].AssetBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot DecodeString")
		return
	}

	blindValueAssetBlind, err := secp256k1.BlindValueGeneratorBlindSum(uint64(slate.Amount), assetBlind[:], savedSlate.Blind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot BlindValueGeneratorBlindSum")
		return
	}

	secretKey, err := secp256k1.BlindSum(t.context, [][]byte{blindValueAssetBlind[:], savedSlate.ExcessBlind[:]}, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot compute secret key")
		return
	}

	partialSignature, err := secp256k1.AggsigSignPartial(t.context, secretKey[:], savedSlate.Nonce[:],
		aggregatedPublicNonce, aggregatedPublicKey, msg)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate receiver's partial signature")
		return
	}

	partialSignatureBytes := secp256k1.AggsigSignaturePartialSerialize(&partialSignature)
	partialSignatureString := hex.EncodeToString(partialSignatureBytes[:])

	// Дополнение slate-ов частичными подписями
	slate.ParticipantData[savedSlate.ParticipantID].PartSig = &partialSignatureString

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return slateBytes, nil
}

func (t *Wallet) AggregateMultipartyFundingTransaction(value uint64, asset string, slate *Slate) (ledgerTxBytes []byte, walletTx *SavedTransaction, err error) {
	// Создаем общий выход
	output, err := t.createMultipartyOutput(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot createMultipartyOutput")
		return
	}
	slate.Transaction.Body.Outputs = []SlateOutput{*output}

	// Формируем общую подпись
	signature, err := t.aggregatePartialSignatures(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregatePartialSignatures")
		return
	}

	// Формируем транзакцию
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

	// Вычисляем msg
	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// verify final sig with pk from excess
	err = secp256k1.AggsigVerifySingle(t.context, &signature, msg, nil, excessPublicKey, excessPublicKey, nil, false)
	if err != nil {
		err = errors.Wrap(err, "AggsigVerifySingle failed to verify the finalSig with excessPublicKey")
		return
	}

	excessSig := secp256k1.AggsigSignatureSerialize(t.context, &signature)

	ledgerTx := ledger.Transaction{
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
		ledgerTx.Body.Inputs = append(ledgerTx.Body.Inputs, o.Input)
	}

	for _, o := range slate.Transaction.Body.Outputs {
		e := t.addSurjectionProof(&o, slate.Transaction.Body.Inputs, slate.Asset)
		if e != nil {
			err = errors.Wrap(e, "cannot addSurjectionProof")
			return
		}
		ledgerTx.Body.Outputs = append(ledgerTx.Body.Outputs, o.Output)
	}

	ledgerTxBytes, err = json.Marshal(ledgerTx)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal ledgerTx to json")
		return
	}

	return
}
