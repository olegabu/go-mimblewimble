package multisig

import (
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-mimblewimble/multisigwallet/multisig/bulletproof"
	. "github.com/olegabu/go-mimblewimble/multisigwallet/types"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func InitMultipartyTransaction(
	wallet Wallet,
	inputs []SavedOutput,
	change uint64,
	fee uint64,
	transactionID uuid.UUID,
	participantID string,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	blind, assetBlind, offset, blindExcess, nonce, changeOutput, err := preparePartyData(wallet, inputs, change)
	if err != nil {
		err = errors.Wrap(err, "cannot preparePartyData")
		return
	}

	commits, err := commitsFromBlinds(wallet.GetContext(), blind[:], blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot get commits from blinds")
		return
	}

	publicBlind := commits[0]
	publicBlindExcess := commits[1]
	publicNonce := commits[2]

	slateInputs := make([]SlateInput, 0)
	for _, input := range inputs {
		inputAssetBlind, e := hex.DecodeString(input.SlateOutput.AssetBlind)
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
		walletOutputs = []SavedOutput{*changeOutput}
	}

	bulletproofsShare, err := bulletproof.GeneratePublicTaus(wallet.GetContext(), blind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot generatePublicTaus")
		return
	}

	var totalAmount uint64
	for _, input := range inputs {
		totalAmount += input.Value
	}
	totalAmount -= change

	slate = &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 1,
		Transaction: SlateTransaction{
			ID:     transactionID,
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
		ParticipantData: map[string]*ParticipantData{participantID: {
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
		Slate:             *slate,
		Nonce:             nonce,
		PartialBlind:      blind,
		PartialAssetBlind: assetBlind,
		ExcessBlind:       blindExcess,
		ParticipantID:     participantID,
	}
	return
}

func SignMultipartyTransaction(wallet Wallet, slates []*Slate, savedSlate *SavedSlate) (slate *Slate, err error) {
	slate, err = combineInitialSlates(wallet, slates)
	if err != nil {
		err = errors.Wrap(err, "cannot combineInitialSlates")
		return
	}

	participantID := savedSlate.ParticipantID

	partialSignature, err := createPartialSignature(wallet, slate, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot createPartialSignature")
		return
	}
	slate.ParticipantData[participantID].PartSig = &partialSignature

	newMultipartyUtxoIsNeccessary := slate.Amount > 0
	if newMultipartyUtxoIsNeccessary {
		assetBlind := savedSlate.PartialAssetBlind
		blind := savedSlate.PartialBlind

		sumPublicTau1, sumPublicTau2, _, commonNonce, e := aggregateBulletproofMPCValues(wallet.GetContext(), slate)
		if e != nil {
			err = errors.Wrap(e, "cannot aggregateBulletproofMPCValues")
			return
		}

		commit, assetCommit, _, _, e := computeMultipartyCommit(wallet.GetContext(), slate)
		if e != nil {
			err = errors.Wrap(e, "cannot computeMultipartyCommit")
			return
		}

		taux, e := bulletproof.ComputeTaux(wallet.GetContext(), uint64(slate.Amount), blind[:], assetBlind[:], commit, assetCommit, sumPublicTau1, sumPublicTau2, commonNonce)
		if e != nil {
			err = errors.Wrap(e, "cannot computeTaux")
			return
		}
		slate.ParticipantData[participantID].BulletproofsShare.Taux = hex.EncodeToString(taux)
	}
	return
}

func AggregateMultipartyTransaction(
	wallet Wallet,
	slates []*Slate,
	savedSlate *SavedSlate,
) (
	transaction *ledger.Transaction,
	savedTransaction SavedTransaction,
	multipartyOutput *SavedOutput,
	err error,
) {
	slate, err := combinePartiallySignedSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "cannot combineSlates")
		return
	}

	signature, err := aggregatePartialSignatures(wallet, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregatePartialSignatures")
		return
	}

	var output *SlateOutput
	newMultipartyUtxoIsNeccessary := slate.Amount > 0
	if newMultipartyUtxoIsNeccessary {
		output, err = createMultipartyOutput(wallet.GetContext(), slate)
		if err != nil {
			err = errors.Wrap(err, "cannot createMultipartyOutput")
			return
		}
		slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, *output)
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

	kernelExcess, err := ledger.CalculateExcess(wallet.GetContext(), inputCommitments, outputCommitments, offsetBytes, uint64(slate.Transaction.Body.Kernels[0].Fee))
	if err != nil {
		err = errors.Wrap(err, "cannot calculate kernel excess")
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(wallet.GetContext(), kernelExcess)
	if err != nil {
		err = errors.Wrap(err, "excessPublicKey: CommitmentToPublicKey failed")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// verify final sig with pk from excess
	err = secp256k1.AggsigVerifySingle(wallet.GetContext(), &signature, msg, nil, excessPublicKey, excessPublicKey, nil, false)
	if err != nil {
		err = errors.Wrap(err, "AggsigVerifySingle failed to verify the finalSig with excessPublicKey")
		return
	}
	excessSig := secp256k1.AggsigSignatureSerialize(wallet.GetContext(), &signature)

	transaction = &ledger.Transaction{
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
		e := addSurjectionProof(wallet.GetContext(), &o, slate.Transaction.Body.Inputs, slate.Asset)
		if e != nil {
			err = errors.Wrap(e, "cannot addSurjectionProof")
			return
		}
		transaction.Body.Outputs = append(transaction.Body.Outputs, o.Output)
	}

	savedTransaction = SavedTransaction{
		Transaction: *transaction,
		Status:      TransactionUnconfirmed,
	}

	if newMultipartyUtxoIsNeccessary {
		multipartyOutput = &SavedOutput{
			SlateOutput:       *output,
			Value:             uint64(slate.Amount),
			PartialBlind:      &savedSlate.PartialBlind,
			PartialAssetBlind: &savedSlate.PartialAssetBlind,
			Asset:             slate.Asset,
			Status:            OutputUnconfirmed,
		}
	}

	return
}

func preparePartyData(wallet Wallet, inputs []SavedOutput, change uint64) (
	blind [32]byte,
	assetBlind [32]byte,
	offset [32]byte,
	blindExcess [32]byte,
	nonce [32]byte,
	changeOutput *SavedOutput,
	err error,
) {
	// generate partial output blind
	blind, _, err = wallet.NewSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}

	// generate partial output asset blind
	assetBlind, _, err = wallet.NewSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}

	// generate random offset
	offset, err = wallet.Nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for offset")
		return
	}

	// generate secret nonce
	nonce, err = wallet.Nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	// compute excess blinding factor
	inputsBlindValueAssetBlinds := make([][]byte, 0)
	for _, input := range inputs {
		blindValueAssetBlind, e := computeBlindValueAssetBlind(wallet, input)
		if e != nil {
			err = errors.Wrap(e, "cannot getBlindValueAssetBlind")
			return
		}
		inputsBlindValueAssetBlinds = append(inputsBlindValueAssetBlinds, blindValueAssetBlind[:])
	}

	// x = change - inputs - offset (now change = 0)
	blindExcess, err = secp256k1.BlindSum(wallet.GetContext(), nil, append(inputsBlindValueAssetBlinds, offset[:]))
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}

	if change > 0 {
		// create change output and remember its blinding factor
		var e error
		changeOutput, _, e = newOutput(wallet, change, ledger.PlainOutput, inputs[0].Asset, OutputUnconfirmed)
		if e != nil {
			err = errors.Wrap(e, "cannot create change output")
			return
		}

		changeBlindValueAssetBlinds, e := computeBlindValueAssetBlind(wallet, *changeOutput)
		if e != nil {
			err = errors.Wrap(e, "cannot getBlindValueAssetBlind")
			return
		}

		blindExcess, e = secp256k1.BlindSum(wallet.GetContext(), [][]byte{blindExcess[:], changeBlindValueAssetBlinds[:]}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot BlindSum")
			return
		}
	}
	return
}

func combineInitialSlates(wallet Wallet, slates []*Slate) (aggregatedSlate *Slate, err error) {
	// TODO: check slates

	inputs := make([]SlateInput, 0)
	outputs := make([]SlateOutput, 0)
	participantDatas := make(map[string]*ParticipantData, 0)
	var totalAmount ledger.Uint64
	var totalOffset [32]byte
	for _, slate := range slates {
		for _, input := range slate.Transaction.Body.Inputs {
			if !input.IsMultiparty {
				inputs = append(inputs, input)
			}
		}
		outputs = append(outputs, slate.Transaction.Body.Outputs...)

		for participantID, participantData := range slate.ParticipantData {
			participantDatas[participantID] = participantData
		}

		offset, err := hex.DecodeString(slate.Transaction.Offset)
		if err != nil {
			return nil, err
		}

		totalOffset, err = secp256k1.BlindSum(wallet.GetContext(), [][]byte{totalOffset[:], offset}, nil)
		if err != nil {
			return nil, err
		}
		totalAmount += slate.Amount
	}

	savedOutput, getOutputErr := wallet.GetOutput(slates[0].Transaction.Body.Inputs[0].Commit)
	if getOutputErr == nil && savedOutput.IsMultiparty {
		inputs = append(inputs, slates[0].Transaction.Body.Inputs[0])
		totalAmount = slates[0].Amount
		for i := 1; i < len(slates); i++ {
			totalAmount -= ledger.Uint64(savedOutput.Value) - slates[i].Amount
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

func combinePartiallySignedSlates(slates []*Slate) (slate *Slate, err error) {
	slate = slates[0]
	for participantID := range slate.ParticipantData {
		correspondingParticipantData, e := findCorrespondingParticipantData(slates, participantID)
		if e != nil {
			err = errors.Wrap(e, "cannot findCorrespondingParticipantData")
			return
		}
		slate.ParticipantData[participantID].PartSig = correspondingParticipantData.PartSig
		slate.ParticipantData[participantID].BulletproofsShare.Taux = correspondingParticipantData.BulletproofsShare.Taux
	}
	return
}

func computeMultipartyCommit(context *secp256k1.Context, slate *Slate) (
	commit *secp256k1.Commitment,
	assetCommit *secp256k1.Generator,
	assetTag *secp256k1.FixedAssetTag,
	aggregatedAssetBlind [32]byte,
	err error,
) {
	publicBlinds, _, _, _, err := getSharedData(context, slate)
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
		aggregatedAssetBlind, e = secp256k1.BlindSum(context, [][]byte{aggregatedAssetBlind[:], assetBlind}, nil)
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

	assetCommit, err = secp256k1.GeneratorGenerateBlinded(context, assetTag.Slice(), aggregatedAssetBlind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to asset")
		return
	}

	commit, err = secp256k1.Commit(context, new([32]byte)[:], uint64(slate.Amount), assetCommit, &secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to value")
		return
	}

	commit, err = secp256k1.CommitSum(context, append(publicBlinds, commit), nil)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum")
		return
	}
	return
}

func createMultipartyOutput(context *secp256k1.Context, slate *Slate) (output *SlateOutput, err error) {
	commit, assetCommit, assetTag, aggregatedAssetBlind, err := computeMultipartyCommit(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot computeMultipartyCommit")
		return
	}

	sumPublicTau1, sumPublicTau2, sumTaux, commonNonce, err := aggregateBulletproofMPCValues(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregateBulletproofMPCValues")
		return
	}

	proof, err := bulletproof.AggregateProof(context, uint64(slate.Amount), commit, assetCommit, sumPublicTau1, sumPublicTau2, sumTaux, commonNonce)
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
