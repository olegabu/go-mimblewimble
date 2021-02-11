package multisig

import (
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-mimblewimble/wallet/multisig/bulletproof"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-mimblewimble/wallet/utils"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func Fund(
	sg SecretGenerator,
	fundingAmount uint64,
	change uint64,
	fee uint64,
	asset string,
	inputs []SavedOutput,
	transactionID uuid.UUID,
	participantID string,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	return initTransaction(sg, fundingAmount, change, fee, asset, inputs, transactionID, participantID)
}

func Spend(
	sg SecretGenerator,
	spendingAmount uint64,
	change uint64,
	fee uint64,
	asset string,
	multipartyOutput SavedOutput,
	transactionID uuid.UUID,
	participantID string,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	return initTransaction(sg, spendingAmount, change, fee, asset, []SavedOutput{multipartyOutput}, transactionID, participantID)
}

func initTransaction(
	sg SecretGenerator,
	amount uint64,
	change uint64,
	fee uint64,
	asset string,
	inputs []SavedOutput,
	transactionID uuid.UUID,
	participantID string,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot create secp256k1 context")
		return
	}
	defer secp256k1.ContextDestroy(context)

	inputsBlindValueAssetBlinds := make([][]byte, 0)
	for _, input := range inputs {
		blindValueAssetBlind, e := computeBlindValueAssetBlind(sg, context, input)
		if e != nil {
			err = errors.Wrap(e, "cannot compute inputBlind + inputValue * inputAssetBlind")
			return
		}
		inputsBlindValueAssetBlinds = append(inputsBlindValueAssetBlinds, blindValueAssetBlind[:])
	}

	partialOffset, err := sg.Nonce(context)
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for partial offset")
		return
	}

	blindExcess, err := secp256k1.BlindSum(context, nil, append(inputsBlindValueAssetBlinds, partialOffset[:]))
	if err != nil {
		err = errors.Wrap(err, "cannot compute blind excess: -Σ(inputBlind + inputValue + inputAssetBlind) - offset")
		return
	}

	var changeOutput *SavedOutput
	if change > 0 {
		var e error
		changeOutput, _, e = utils.NewOutput(sg, context, change, ledger.PlainOutput, inputs[0].Asset, OutputUnconfirmed)
		if e != nil {
			err = errors.Wrap(e, "cannot create change output")
			return
		}

		changeBlindValueAssetBlinds, e := computeBlindValueAssetBlind(sg, context, *changeOutput)
		if e != nil {
			err = errors.Wrap(e, "cannot compute changeBlind + changeValue * changeAssetBlind")
			return
		}

		blindExcess, e = secp256k1.BlindSum(context, [][]byte{blindExcess[:], changeBlindValueAssetBlinds[:]}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot compute blind excess: changeBlind + changeValue * changeAssetBlind -Σ(inputBlind + inputValue + inputAssetBlind) - offset")
			return
		}
	}

	nonce, err := sg.Nonce(context)
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	commits, err := commitsFromBlinds(context, blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot compute public excess and public nonce")
		return
	}
	publicBlindExcess := commits[0]
	publicNonce := commits[1]

	slateInputs := make([]SlateInput, 0)
	for _, input := range inputs {
		slateInput := SlateInput{
			Input: ledger.Input{
				Features:    input.Features,
				Commit:      input.Commit,
				AssetCommit: input.AssetCommit,
			},
			AssetTag:     input.AssetTag,
			AssetBlind:   input.SlateOutput.AssetBlind,
			IsMultiparty: input.IsMultiparty,
		}
		slateInputs = append(slateInputs, slateInput)
	}

	slateOutputs := make([]SlateOutput, 0)
	if changeOutput != nil {
		slateOutputs = append(slateOutputs, changeOutput.SlateOutput)
		walletOutputs = []SavedOutput{*changeOutput}
	}

	slate = &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 1,
		Transaction: SlateTransaction{
			ID:     transactionID,
			Offset: hex.EncodeToString(partialOffset[:]),
			Body: SlateTransactionBody{
				Inputs:  slateInputs,
				Outputs: slateOutputs,
				Kernels: []ledger.TxKernel{{
					Features: ledger.PlainKernel,
					Fee:      ledger.Uint64(fee),
				}},
			},
		},
		Amount:     ledger.Uint64(amount),
		Fee:        ledger.Uint64(fee),
		Height:     0,
		LockHeight: 0,
		ParticipantData: map[string]*ParticipantData{participantID: {
			PublicBlindExcess:   publicBlindExcess.String(),
			PublicNonce:         publicNonce.String(),
			IsMultisigFundOwner: true,
		}},
		Asset: inputs[0].Asset,
	}

	if len(inputs) == 1 && inputs[0].IsMultiparty {
		slate.MultisigFundBalance = &inputs[0].Value
	}

	savedSlate = &SavedSlate{
		Slate:         *slate,
		Nonce:         nonce,
		ExcessBlind:   blindExcess,
		ParticipantID: participantID,
	}

	if newMultipartyUtxoIsNeccessary(slate) {
		blind, _, e := sg.NewSecret(context)
		if e != nil {
			err = errors.Wrap(e, "cannot generate partial blind for multiparty output")
			return
		}

		commits, e := commitsFromBlinds(context, blind[:])
		if e != nil {
			err = errors.Wrap(e, "cannot compute public partial blind for multiparty output")
			return
		}
		publicBlind := commits[0]

		assetBlind, _, e := sg.NewSecret(context)
		if e != nil {
			err = errors.Wrap(e, "cannot generate partial asset blind for multiparty output")
			return
		}

		bulletproofShare, e := bulletproof.GeneratePublicTaus(context, blind[:])
		if e != nil {
			err = errors.Wrap(e, "cannot generate public taus during the first step of the bulletproof mpc")
			return
		}

		slate.ParticipantData[participantID].PublicBlind = publicBlind.String()
		slate.ParticipantData[participantID].AssetBlind = hex.EncodeToString(assetBlind[:])
		slate.ParticipantData[participantID].BulletproofShare = bulletproofShare

		savedSlate.Slate = *slate
		savedSlate.PartialBlind = blind
		savedSlate.PartialAssetBlind = assetBlind
	}

	return
}

func Combine(context *secp256k1.Context, slates []*Slate) (aggregatedSlate *Slate, err error) {
	err = validateInitialSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "initial slates are not valid")
		return
	}

	inputs, outputs := []SlateInput{}, []SlateOutput{}
	participantDatas := make(map[string]*ParticipantData, 0)
	var totalOffset [32]byte
	var amount ledger.Uint64

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

		totalOffset, err = secp256k1.BlindSum(context, [][]byte{totalOffset[:], offset}, nil)
		if err != nil {
			return nil, err
		}

		amount += slate.Amount
	}

	if slates[0].Transaction.Body.Inputs[0].IsMultiparty {
		inputs = append(inputs, slates[0].Transaction.Body.Inputs[0])
		amount = slates[0].Amount
	}

	aggregatedSlate = slates[0]
	aggregatedSlate.NumParticipants = uint(len(slates))
	aggregatedSlate.Transaction.Offset = hex.EncodeToString(totalOffset[:])
	aggregatedSlate.Transaction.Body.Inputs = inputs
	aggregatedSlate.Transaction.Body.Outputs = outputs
	aggregatedSlate.Amount = amount
	aggregatedSlate.ParticipantData = participantDatas
	return
}

func Sign(slates []*Slate, savedSlate *SavedSlate) (slate *Slate, err error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot create secp256k1 context")
		return
	}
	defer secp256k1.ContextDestroy(context)

	slate, err = Combine(context, slates)
	if err != nil {
		err = errors.Wrap(err, "cannot сombine initial slates")
		return
	}

	partialSignature, err := createPartialSignature(context, slate, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot create partial signature")
		return
	}
	slate.ParticipantData[savedSlate.ParticipantID].PartSig = &partialSignature

	if newMultipartyUtxoIsNeccessary(slate) {
		assetBlind := savedSlate.PartialAssetBlind
		blind := savedSlate.PartialBlind

		sumPublicTau1, sumPublicTau2, _, commonNonce, e := aggregateBulletproofMPCValues(context, slate)
		if e != nil {
			err = errors.Wrap(e, "cannot compute sum of publicTau1s and publicTau2s")
			return
		}

		commit, assetCommit, _, _, e := computeMultipartyCommit(context, slate, savedSlate)
		if e != nil {
			err = errors.Wrap(e, "cannot compute multiparty output's commitment and asset's generator")
			return
		}

		value := getMultipartyOutputValue(slate)
		taux, e := bulletproof.ComputeTaux(context, value, blind[:], assetBlind[:], commit, assetCommit, sumPublicTau1, sumPublicTau2, commonNonce)
		if e != nil {
			err = errors.Wrap(e, "cannot compute taux during the second step of bulletproof mpc")
			return
		}
		slate.ParticipantData[savedSlate.ParticipantID].BulletproofShare.Taux = hex.EncodeToString(taux)
	}

	slate.ParticipantData = map[string]*ParticipantData{savedSlate.ParticipantID: slate.ParticipantData[savedSlate.ParticipantID]}
	return
}

func Aggregate(
	slates []*Slate,
	savedSlate *SavedSlate,
) (
	transaction *ledger.Transaction,
	savedTransaction SavedTransaction,
	multipartyOutput *SavedOutput,
	err error,
) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot create secp256k1 context")
		return
	}
	defer secp256k1.ContextDestroy(context)

	slate, err := combinePartiallySignedSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "cannot combine partially signed slates")
		return
	}

	signature, err := aggregatePartialSignatures(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregate partial signatures")
		return
	}

	var output *SlateOutput
	if newMultipartyUtxoIsNeccessary(slate) {
		output, err = createMultipartyOutput(context, slate, savedSlate)
		if err != nil {
			err = errors.Wrap(err, "cannot create multiparty output")
			return
		}
		slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, *output)
	}

	var inputCommitments, outputCommitments []*secp256k1.Commitment
	for _, input := range slate.Transaction.Body.Inputs {
		com, e := secp256k1.CommitmentFromString(input.Commit)
		if e != nil {
			err = errors.Wrap(e, "cannot parse input's commit")
			return
		}
		inputCommitments = append(inputCommitments, com)
	}

	for _, output := range slate.Transaction.Body.Outputs {
		com, e := secp256k1.CommitmentFromString(output.Commit)
		if e != nil {
			err = errors.Wrap(e, "cannot parse output's commit")
			return
		}
		outputCommitments = append(outputCommitments, com)
	}

	offset, err := hex.DecodeString(slate.Transaction.Offset)
	if err != nil {
		err = errors.Wrap(err, "cannot parse offset")
		return
	}

	kernelExcess, err := ledger.CalculateExcess(context, inputCommitments, outputCommitments, offset, uint64(slate.Transaction.Body.Kernels[0].Fee))
	if err != nil {
		err = errors.Wrap(err, "cannot calculate kernel excess")
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(context, kernelExcess)
	if err != nil {
		err = errors.Wrap(err, "cannot convert kernelExcess from Commitment to PublicKey")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	err = secp256k1.AggsigVerifySingle(context, &signature, msg, nil, excessPublicKey, excessPublicKey, nil, false)
	if err != nil {
		err = errors.Wrap(err, "failed to verify aggregated signature with excess as public key")
		return
	}
	excessSig := secp256k1.AggsigSignatureSerialize(context, &signature)

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
		e := utils.AddSurjectionProof(context, &o, slate.Transaction.Body.Inputs, slate.Asset)
		if e != nil {
			err = errors.Wrap(e, "cannot add surjection proof to output")
			return
		}
		transaction.Body.Outputs = append(transaction.Body.Outputs, o.Output)
	}

	savedTransaction = SavedTransaction{
		Transaction: *transaction,
		Status:      TransactionUnconfirmed,
	}

	if newMultipartyUtxoIsNeccessary(slate) {
		value := getMultipartyOutputValue(slate)
		multipartyOutput = &SavedOutput{
			SlateOutput:       *output,
			Value:             value,
			PartialBlind:      &savedSlate.PartialBlind,
			PartialAssetBlind: &savedSlate.PartialAssetBlind,
			Asset:             slate.Asset,
			Status:            OutputUnconfirmed,
		}
	}
	return
}

func combinePartiallySignedSlates(slates []*Slate) (slate *Slate, err error) {
	err = validateInitialSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "slates are not valid")
		return
	}

	// TODO: add additional checks

	slate = slates[0]
	for _, participantSlate := range slates {
		for partyID, participantData := range participantSlate.ParticipantData {
			slate.ParticipantData[partyID] = participantData
		}
	}
	return
}

func validateInitialSlates(slates []*Slate) (err error) {
	if slates == nil || len(slates) == 0 {
		return errors.New("slates is nil or empty")
	}

	slate := slates[0]
	ok := true
	for i := 1; i < len(slates); i++ {
		ok = ok && slate.VersionInfo == slates[i].VersionInfo
		ok = ok && slate.Transaction.ID == slates[i].Transaction.ID
		ok = ok && slate.Asset == slates[i].Asset
		ok = ok && slate.Transaction.Body.Kernels[0].Fee == slates[i].Transaction.Body.Kernels[0].Fee
	}

	if !ok {
		return errors.New("slates don't match to each other")
	}
	return
}

func computeMultipartyCommit(context *secp256k1.Context, slate *Slate, savedSlate *SavedSlate) (
	commit *secp256k1.Commitment,
	assetCommit *secp256k1.Generator,
	assetTag *secp256k1.FixedAssetTag,
	aggregatedAssetBlind [32]byte,
	err error,
) {
	publicBlinds := make([]*secp256k1.Commitment, 0)
	for partyID, partyData := range slate.ParticipantData {
		if !partyData.IsMultisigFundOwner {
			continue
		}

		assetBlind, e := hex.DecodeString(partyData.AssetBlind)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse asset blind of participant with id %s", partyID)
			return
		}

		aggregatedAssetBlind, e = secp256k1.BlindSum(context, [][]byte{aggregatedAssetBlind[:], assetBlind}, nil)
		if e != nil {
			err = errors.Wrapf(e, "cannot compute aggregated asset blind")
			return
		}

		publicBlind, e := secp256k1.CommitmentFromString(partyData.PublicBlind)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse public blind of participant with id %s", partyID)
			return
		}
		publicBlinds = append(publicBlinds, publicBlind)
	}

	assetTag, err = secp256k1.FixedAssetTagParse(ledger.AssetSeed(slate.Asset))
	if err != nil {
		err = errors.Wrap(err, "cannot get asset tag")
		return
	}

	assetCommit, err = secp256k1.GeneratorGenerateBlinded(context, assetTag.Slice(), aggregatedAssetBlind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create asset commit")
		return
	}

	value := getMultipartyOutputValue(slate)
	commit, err = secp256k1.Commit(context, new([32]byte)[:], value, assetCommit, &secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot compute: value * (H + aggregatedAssetBlind * G)")
		return
	}

	commit, err = secp256k1.CommitSum(context, append(publicBlinds, commit), nil)
	if err != nil {
		err = errors.Wrap(err, "cannot compute commitment for multiparty output: value * (H + aggregatedAssetBlind * G) + ΣPublicBlind")
		return
	}
	return
}

func createMultipartyOutput(context *secp256k1.Context, slate *Slate, savedSlate *SavedSlate) (output *SlateOutput, err error) {
	commit, assetCommit, assetTag, aggregatedAssetBlind, err := computeMultipartyCommit(context, slate, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot compute commitment for multiparty output")
		return
	}

	sumPublicTau1, sumPublicTau2, sumTaux, commonNonce, err := aggregateBulletproofMPCValues(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregate publicTau1s, publicTau2s, tauxes or nonces")
		return
	}

	value := getMultipartyOutputValue(slate)
	proof, err := bulletproof.AggregateProof(context, value, commit, assetCommit, sumPublicTau1, sumPublicTau2, sumTaux, commonNonce)
	if err != nil {
		err = errors.Wrap(err, "cannot compute range proof during the third step of bulletproof mpc")
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

func getMultipartyOutputValue(slate *Slate) uint64 {
	var value uint64
	if slate.MultisigFundBalance == nil {
		value = uint64(slate.Amount)
	} else {
		value = *slate.MultisigFundBalance - uint64(slate.Amount)
	}
	return value
}

func newMultipartyUtxoIsNeccessary(slate *Slate) bool {
	return slate.MultisigFundBalance == nil || *slate.MultisigFundBalance > uint64(slate.Amount)
}
