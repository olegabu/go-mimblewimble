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

func InitMultisigTransaction(
	wallet Wallet,
	amount uint64,
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
	// compute excess blinding factor
	inputsBlindValueAssetBlinds := make([][]byte, 0)
	for _, input := range inputs {
		blindValueAssetBlind, e := computeBlindValueAssetBlind(wallet, input)
		if e != nil {
			err = errors.Wrap(e, "cannot computeBlindValueAssetBlind")
			return
		}
		inputsBlindValueAssetBlinds = append(inputsBlindValueAssetBlinds, blindValueAssetBlind[:])
	}

	// generate random offset
	offset, err := wallet.Nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for offset")
		return
	}

	// x = change - inputs - offset (now change = 0)
	blindExcess, err := secp256k1.BlindSum(wallet.GetContext(), nil, append(inputsBlindValueAssetBlinds, offset[:]))
	if err != nil {
		err = errors.Wrap(err, "cannot compute blind excess")
		return
	}

	var changeOutput *SavedOutput
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
			err = errors.Wrap(e, "cannot computeBlindValueAssetBlind")
			return
		}

		blindExcess, e = secp256k1.BlindSum(wallet.GetContext(), [][]byte{blindExcess[:], changeBlindValueAssetBlinds[:]}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot compute blind excess")
			return
		}
	}

	// generate secret nonce
	nonce, err := wallet.Nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	commits, err := commitsFromBlinds(wallet.GetContext(), blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot get commits from blinds")
		return
	}

	publicBlindExcess := commits[0]
	publicNonce := commits[1]

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
		// generate partial output blind
		blind, _, e := wallet.NewSecret()
		if e != nil {
			err = errors.Wrap(e, "cannot get NewSecret")
			return
		}

		commits, e := commitsFromBlinds(wallet.GetContext(), blind[:])
		if e != nil {
			err = errors.Wrap(e, "cannot get commits from blinds")
			return
		}
		publicBlind := commits[0]

		// generate partial output asset blind
		assetBlind, _, e := wallet.NewSecret()
		if e != nil {
			err = errors.Wrap(e, "cannot get NewSecret")
			return
		}

		bulletproofsShare, e := bulletproof.GeneratePublicTaus(wallet.GetContext(), blind[:])
		if e != nil {
			err = errors.Wrap(e, "cannot GeneratePublicTaus")
			return
		}

		slate.ParticipantData[participantID].PublicBlind = publicBlind.String()
		slate.ParticipantData[participantID].AssetBlind = hex.EncodeToString(assetBlind[:])
		slate.ParticipantData[participantID].BulletproofsShare = bulletproofsShare

		savedSlate.Slate = *slate
		savedSlate.PartialBlind = blind
		savedSlate.PartialAssetBlind = assetBlind
	}

	return
}

func SignMultisigTransaction(wallet Wallet, slates []*Slate, savedSlate *SavedSlate) (slate *Slate, err error) {
	slate, err = CombineInitialSlates(wallet, slates)
	if err != nil {
		err = errors.Wrap(err, "cannot CombineInitialSlates")
		return
	}

	partialSignature, err := createPartialSignature(wallet, slate, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot createPartialSignature")
		return
	}
	slate.ParticipantData[savedSlate.ParticipantID].PartSig = &partialSignature

	if newMultipartyUtxoIsNeccessary(slate) {
		assetBlind := savedSlate.PartialAssetBlind
		blind := savedSlate.PartialBlind

		sumPublicTau1, sumPublicTau2, _, commonNonce, e := aggregateBulletproofMPCValues(wallet.GetContext(), slate)
		if e != nil {
			err = errors.Wrap(e, "cannot aggregateBulletproofMPCValues")
			return
		}

		commit, assetCommit, _, _, e := computeMultipartyCommit(wallet.GetContext(), slate, savedSlate)
		if e != nil {
			err = errors.Wrap(e, "cannot computeMultipartyCommit")
			return
		}

		value := getMultipartyOutputValue(slate)
		taux, e := bulletproof.ComputeTaux(wallet.GetContext(), value, blind[:], assetBlind[:], commit, assetCommit, sumPublicTau1, sumPublicTau2, commonNonce)
		if e != nil {
			err = errors.Wrap(e, "cannot ComputeTaux")
			return
		}
		slate.ParticipantData[savedSlate.ParticipantID].BulletproofsShare.Taux = hex.EncodeToString(taux)
	}
	return
}

func AggregateMultisigTransaction(
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
		err = errors.Wrap(err, "cannot combinePartiallySignedSlates")
		return
	}

	signature, err := aggregatePartialSignatures(wallet, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregatePartialSignatures")
		return
	}

	var output *SlateOutput
	if newMultipartyUtxoIsNeccessary(slate) {
		output, err = createMultipartyOutput(wallet.GetContext(), slate, savedSlate)
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

func CombineInitialSlates(wallet Wallet, slates []*Slate) (aggregatedSlate *Slate, err error) {
	err = validateInitialSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "cannot validateInitialSlates")
		return
	}

	inputs := make([]SlateInput, 0)
	outputs := make([]SlateOutput, 0)
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

		totalOffset, err = secp256k1.BlindSum(wallet.GetContext(), [][]byte{totalOffset[:], offset}, nil)
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

func combinePartiallySignedSlates(slates []*Slate) (slate *Slate, err error) {
	// TODO: add checks
	err = validateInitialSlates(slates)
	if err != nil {
		err = errors.Wrap(err, "cannot validateInitialSlates")
		return
	}

	slate = slates[0]
	for participantID := range slate.ParticipantData {
		correspondingParticipantData, e := findCorrespondingParticipantData(slates, participantID)
		if e != nil {
			err = errors.Wrap(e, "cannot findCorrespondingParticipantData")
			return
		}
		slate.ParticipantData[participantID].PartSig = correspondingParticipantData.PartSig

		if newMultipartyUtxoIsNeccessary(slates[0]) && slate.ParticipantData[participantID].IsMultisigFundOwner {
			slate.ParticipantData[participantID].BulletproofsShare.Taux = correspondingParticipantData.BulletproofsShare.Taux
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
		return errors.New("slates do not match to each other")
	}
	return nil
}

func computeMultipartyCommit(context *secp256k1.Context, slate *Slate, savedSlate *SavedSlate) (
	commit *secp256k1.Commitment,
	assetCommit *secp256k1.Generator,
	assetTag *secp256k1.FixedAssetTag,
	aggregatedAssetBlind [32]byte,
	err error,
) {
	publicBlinds := make([]*secp256k1.Commitment, 0)
	for _, party := range slate.ParticipantData {
		if !party.IsMultisigFundOwner {
			continue
		}

		assetBlind, e := hex.DecodeString(party.AssetBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot DecodeString")
			return
		}

		aggregatedAssetBlind, e = secp256k1.BlindSum(context, [][]byte{aggregatedAssetBlind[:], assetBlind}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot BlindSum")
			return
		}

		publicBlind, e := secp256k1.CommitmentFromString(party.PublicBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentFromString")
			return
		}
		publicBlinds = append(publicBlinds, publicBlind)
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

	value := getMultipartyOutputValue(slate)
	commit, err = secp256k1.Commit(context, new([32]byte)[:], value, assetCommit, &secp256k1.GeneratorG)
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

func createMultipartyOutput(context *secp256k1.Context, slate *Slate, savedSlate *SavedSlate) (output *SlateOutput, err error) {
	commit, assetCommit, assetTag, aggregatedAssetBlind, err := computeMultipartyCommit(context, slate, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot computeMultipartyCommit")
		return
	}

	sumPublicTau1, sumPublicTau2, sumTaux, commonNonce, err := aggregateBulletproofMPCValues(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregateBulletproofMPCValues")
		return
	}

	value := getMultipartyOutputValue(slate)
	proof, err := bulletproof.AggregateProof(context, value, commit, assetCommit, sumPublicTau1, sumPublicTau2, sumTaux, commonNonce)
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
