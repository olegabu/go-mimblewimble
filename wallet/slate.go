package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) NewSlate(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []SavedOutput,
	receiveAmount uint64,
	receiveAsset string,
	extraData []byte,
) (
	slateBytes []byte,
	walletOutputs []SavedOutput,
	walletSlate *SavedSlate,
	err error,
) {
	slateInputs, walletOutputs, blindExcess, err := t.inputsAndOutputs(
		amount,
		fee,
		asset,
		change,
		walletInputs,
		receiveAmount,
		receiveAsset,
		nil)
	if err != nil {
		err = errors.Wrap(err, "cannot create slateInputs and walletOutputs")
		return
	}

	// generate secret nonce
	nonce, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	// generate random kernel offset
	kernelOffset, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for kernelOffset")
		return
	}

	// subtract kernel offset from blinding excess
	sumBlinds, err := secp256k1.BlindSum(t.context, [][]byte{blindExcess[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}

	publicBlindExcess, err := t.pubKeyFromSecretKey(sumBlinds[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlindExcess")
		return
	}

	publicNonce, err := t.pubKeyFromSecretKey(nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
	}

	var slateOutputs []SlateOutput
	for _, o := range walletOutputs {
		slateOutputs = append(slateOutputs, o.SlateOutput)
	}

	slate := &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 2,
		Transaction: SlateTransaction{
			ID:     uuid.New(),
			Offset: hex.EncodeToString(kernelOffset[:]),
			Body: SlateTransactionBody{
				Inputs:  slateInputs,
				Outputs: slateOutputs,
				Kernels: []ledger.TxKernel{{
					Features:   ledger.PlainKernel,
					Fee:        ledger.Uint64(fee),
					LockHeight: 0,
					Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
					ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					ExtraData:  extraData,
				}},
			},
		},
		Amount:     ledger.Uint64(amount),
		Fee:        ledger.Uint64(fee),
		Height:     0,
		LockHeight: 0,
		ParticipantData: []ParticipantData{{
			ID:                0,
			PublicBlindExcess: publicBlindExcess.Hex(t.context),
			PublicNonce:       publicNonce.Hex(t.context),
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
		}},
		Asset:         asset,
		ReceiveAmount: ledger.Uint64(receiveAmount),
		ReceiveAsset:  receiveAsset,
	}

	walletSlate = &SavedSlate{
		Slate: *slate,
		Nonce: nonce,
		Blind: sumBlinds,
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) inputsAndOutputs(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []SavedOutput,
	receiveAmount uint64,
	receiveAsset string,
	outputBlind []byte,
) (
	slateInputs []SlateInput,
	walletOutputs []SavedOutput,
	blindExcess [32]byte,
	err error,
) {
	// loop thru wallet slateInputs to turn them into slateInputs, sum their values,
	// collect walletInput blinding factors (negative)
	var inputsTotal uint64
	var inputBlinds [][]byte
	for _, walletInput := range walletInputs {
		inputsTotal += walletInput.Value

		var blind []byte
		if walletInput.Blind == nil {
			// re-create child secret key from its saved index and use it as this walletInput's blind
			secret, e := t.secret(walletInput.Index)
			if e != nil {
				err = errors.Wrapf(e, "cannot get secret for walletInput with key index %d", walletInput.Index)
				return
			}
			blind = secret[:]
		} else {
			blind = walletInput.Blind[:]
		}

		assetSecret, e := t.secret(walletInput.AssetIndex)
		if e != nil {
			err = errors.Wrapf(e, "cannot get assetSecret for walletInput with key index %d", walletInput.AssetIndex)
			return
		}

		assetBlind := assetSecret[:]

		// r + v*r_a
		valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(walletInput.Value, assetBlind, blind)
		if e != nil {
			err = errors.Wrap(e, "cannot calculate valueAssetBlind")
			return
		}

		inputBlinds = append(inputBlinds, valueAssetBlind[:])

		slateInput := SlateInput{
			Input: ledger.Input{
				Features:    walletInput.Features,
				Commit:      walletInput.Commit,
				AssetCommit: walletInput.AssetCommit,
			},
			AssetTag:   walletInput.AssetTag,
			AssetBlind: hex.EncodeToString(assetBlind),
		}

		slateInputs = append(slateInputs, slateInput)
	}

	// make sure that amounts provided in walletInput parameters do sum up (inputsValue - amount - fee - change == 0)
	if amount+change+fee != inputsTotal {
		err = errors.New("amounts don't sum up (amount + change + fee != inputsTotal)")
		return
	}

	var outputBlinds [][]byte

	// create change output and remember its blinding factor
	if change > 0 {
		changeOutput, changeBlind, e := t.newOutput(change, ledger.PlainOutput, asset, OutputUnconfirmed, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot create change output")
			return
		}
		outputBlinds = append(outputBlinds, changeBlind)
		walletOutputs = append(walletOutputs, *changeOutput)
	}

	if receiveAmount > 0 {
		receiveOutput, receiveBlind, e := t.newOutput(receiveAmount, ledger.PlainOutput, receiveAsset, OutputUnconfirmed, outputBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot create receive output")
			return
		}
		outputBlinds = append(outputBlinds, receiveBlind)
		walletOutputs = append(walletOutputs, *receiveOutput)
	}

	// sum up slateInputs(-) and walletOutputs(+) blinding factors
	blindExcess, err = secp256k1.BlindSum(t.context, outputBlinds, inputBlinds)
	if err != nil {
		err = errors.Wrap(err, "cannot create blinding excess sum")
		return
	}

	return
}

func (t *Wallet) NewResponse(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []SavedOutput,
	receiveAmount uint64,
	receiveAsset string,
	inSlate *Slate,
	outputBlind []byte,
) (
	outSlateBytes []byte,
	walletOutputs []SavedOutput,
	walletSlate *SavedSlate,
	err error,
) {
	slateInputs, walletOutputs, blindExcess, err := t.inputsAndOutputs(
		amount,
		fee,
		asset,
		change,
		walletInputs,
		receiveAmount,
		receiveAsset,
		outputBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot create slateInputs and walletOutputs")
		return
	}

	inSlate.Transaction.Body.Inputs = append(inSlate.Transaction.Body.Inputs, slateInputs...)

	// add responder output (receiver's in Send, payer's change in Invoice)
	for _, o := range walletOutputs {
		inSlate.Transaction.Body.Outputs = append(inSlate.Transaction.Body.Outputs, o.SlateOutput)
	}

	receiverPublicBlind, err := t.pubKeyFromSecretKey(blindExcess[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlind")
		return
	}

	// choose receiver nonce and calculate its public key
	receiverNonce, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}
	receiverPublicNonce, err := t.pubKeyFromSecretKey(receiverNonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
	}

	// parse out sender public blind and public nonce
	senderPublicBlind := t.context.PublicKeyFromHex(inSlate.ParticipantData[0].PublicBlindExcess)
	if senderPublicBlind == nil {
		err = errors.Wrap(err, "cannot get senderPublicBlindExcess")
		return
	}
	senderPublicNonce := t.context.PublicKeyFromHex(inSlate.ParticipantData[0].PublicNonce)
	if senderPublicNonce == nil {
		err = errors.Wrap(err, "cannot get senderPublicNonce")
		return
	}

	// Combine sender and receiver public blinds and nonces
	sumPublicBlinds, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicBlindsBytes")
		return
	}
	sumPublicNonces, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicNoncesBytes")
		return
	}

	// Calculate message digest for the kernel signature
	msg := ledger.KernelSignatureMessage(inSlate.Transaction.Body.Kernels[0])

	// Create Receiver's partial signature
	receiverPartSig, err := secp256k1.AggsigSignPartial(
		t.context,
		blindExcess[:], receiverNonce[:],
		sumPublicNonces, sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate receiver's partial signature")
		return
	}

	// Update slate with the receiver's info
	receiverPartSigBytes := secp256k1.AggsigSignaturePartialSerialize(&receiverPartSig)
	receiverPartSigString := hex.EncodeToString(receiverPartSigBytes[:])
	inSlate.ParticipantData = append(inSlate.ParticipantData, ParticipantData{
		ID:                1,
		PublicBlindExcess: receiverPublicBlind.Hex(t.context),
		PublicNonce:       receiverPublicNonce.Hex(t.context),
		PartSig:           &receiverPartSigString,
		Message:           nil,
		MessageSig:        nil,
	})

	outSlateBytes, err = json.Marshal(inSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	walletSlate = &SavedSlate{
		Slate: *inSlate,
		Nonce: receiverNonce,
	}

	return
}

func (t *Wallet) NewTransaction(
	responseSlate *Slate,
	senderSlate *SavedSlate,
) (
	ledgerTxBytes []byte,
	walletTx SavedTransaction,
	err error,
) {
	// get secret keys from sender's responseSlate that has blind and secret nonces
	senderBlind := senderSlate.Blind[:]
	senderNonce := senderSlate.Nonce[:]
	// calculate public keys from secret keys
	senderPublicBlind, _ := t.pubKeyFromSecretKey(senderBlind)
	senderPublicNonce, _ := t.pubKeyFromSecretKey(senderNonce)

	// parse out public blinds and nonces for both sender and receiver from the responseSlate
	if len(responseSlate.ParticipantData) != 2 {
		err = errors.New("expected 2 entries in ParticipantData")
		return
	}

	if senderSlate.Amount != responseSlate.Amount || senderSlate.Asset != responseSlate.Asset || senderSlate.ReceiveAmount != responseSlate.ReceiveAmount || senderSlate.ReceiveAsset != responseSlate.ReceiveAsset {
		err = errors.Errorf("amounts and assets in the response slate do not match; sent(%d %s %d %s) received(%d %s %d %s)",
			senderSlate.Amount, senderSlate.Asset, senderSlate.ReceiveAmount, senderSlate.ReceiveAsset,
			responseSlate.Amount, responseSlate.Asset, responseSlate.ReceiveAmount, responseSlate.ReceiveAsset)
		return

	}

	// get public keys from responseSlate
	senderPublicBlindFromResponseSlate := t.context.PublicKeyFromHex(responseSlate.ParticipantData[0].PublicBlindExcess)
	senderPublicNonceFromResponseSlate := t.context.PublicKeyFromHex(responseSlate.ParticipantData[0].PublicNonce)

	// verify the response we've got from Receiver has Sender's public key and secret unchanged
	if (0 != bytes.Compare(senderPublicBlind.Bytes(t.context), senderPublicBlindFromResponseSlate.Bytes(t.context))) ||
		(0 != bytes.Compare(senderPublicNonce.Bytes(t.context), senderPublicNonceFromResponseSlate.Bytes(t.context))) {
		err = errors.Wrap(err, "public keys mismatch, calculated values are not the same as loaded from responseSlate")
		return
	}

	receiverPublicBlind := t.context.PublicKeyFromHex(responseSlate.ParticipantData[1].PublicBlindExcess)
	receiverPublicNonce := t.context.PublicKeyFromHex(responseSlate.ParticipantData[1].PublicNonce)

	// combine sender and receiver public blinds and nonces
	sumPublicBlinds, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicBlinds")
		return
	}
	sumPublicNonces, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicNonces")
		return
	}

	// calculate message hash
	msg := ledger.KernelSignatureMessage(responseSlate.Transaction.Body.Kernels[0])

	// decode receiver's partial signature
	receiverPartSigBytes, err := hex.DecodeString(*responseSlate.ParticipantData[1].PartSig)
	if err != nil {
		err = errors.Wrap(err, "cannot decode receiverPartSigBytes from hex")
		return
	}
	receiverPartSig, err := secp256k1.AggsigSignaturePartialParse(receiverPartSigBytes)
	if err != nil {
		err = errors.Wrap(err, "cannot parse receiverPartialSig from bytes")
		return
	}

	// verify receiver's partial signature
	err = secp256k1.AggsigVerifyPartial(
		t.context,
		&receiverPartSig,
		sumPublicNonces,
		receiverPublicBlind,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify receiver partial signature")
		return
	}

	// calculate sender's partial signature
	senderPartSig, err := secp256k1.AggsigSignPartial(
		t.context,
		senderBlind,
		senderNonce,
		sumPublicNonces,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate sender partial signature")
		return
	}

	// verify sender's partial signature
	err = secp256k1.AggsigVerifyPartial(
		t.context,
		&senderPartSig,
		sumPublicNonces,
		senderPublicBlind,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify sender partial signature")
		return
	}

	// add sender and receiver partial signatures
	finalSig, err := secp256k1.AggsigAddSignaturesSingle(
		t.context,
		[]*secp256k1.AggsigSignaturePartial{
			&senderPartSig,
			&receiverPartSig,
		},
		sumPublicNonces)
	if err != nil {
		err = errors.Wrap(err, "cannot add sender and receiver partial signatures")
		return
	}

	// verify final signature
	err = secp256k1.AggsigVerifySingle(
		t.context,
		&finalSig,
		msg,
		nil,
		sumPublicBlinds,
		sumPublicBlinds,
		nil,
		false,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify excess signature")
		return
	}

	slateTx := responseSlate.Transaction

	var inputCommitments, outputCommitments []*secp256k1.Commitment

	// collect input commitments
	for _, input := range slateTx.Body.Inputs {
		com, e := secp256k1.CommitmentFromString(input.Commit)
		if e != nil {
			err = errors.Wrap(e, "error parsing input commitment")
			return
		}
		inputCommitments = append(inputCommitments, com)
	}

	// collect output commitments
	for _, output := range slateTx.Body.Outputs {
		com, e := secp256k1.CommitmentFromString(output.Commit)
		if e != nil {
			err = errors.Wrap(e, "error parsing output commitment")
			return
		}
		outputCommitments = append(outputCommitments, com)
	}

	offsetBytes, err := hex.DecodeString(slateTx.Offset)
	if err != nil {
		err = errors.Wrap(err, "cannot get offsetBytes")
		return
	}

	kernelExcess, err := ledger.CalculateExcess(
		t.context,
		inputCommitments,
		outputCommitments,
		offsetBytes,
		uint64(slateTx.Body.Kernels[0].Fee))
	if err != nil {
		err = errors.Wrap(err, "cannot calculate kernel excess")
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(t.context, kernelExcess)
	if err != nil {
		err = errors.Wrap(err, "excessPublicKey: CommitmentToPublicKey failed")
		return
	}

	// verify final sig with pk from excess
	err = secp256k1.AggsigVerifySingle(
		t.context,
		&finalSig,
		msg,
		sumPublicNonces,
		excessPublicKey,
		excessPublicKey,
		nil,
		false)
	if err != nil {
		err = errors.Wrap(err, "AggsigVerifySingle failed to verify the finalSig with excessPublicKey")
		return
	}

	excessSig := secp256k1.AggsigSignatureSerialize(t.context, &finalSig)

	ledgerTx := ledger.Transaction{
		Offset: slateTx.Offset,
		ID:     slateTx.ID,
		Body: ledger.TransactionBody{
			Kernels: []ledger.TxKernel{
				{
					Excess:    kernelExcess.String(),
					ExcessSig: hex.EncodeToString(excessSig[:]),
					ExtraData: slateTx.Body.Kernels[0].ExtraData,
				},
			},
		},
	}

	for _, o := range slateTx.Body.Inputs {
		ledgerTx.Body.Inputs = append(ledgerTx.Body.Inputs, o.Input)
	}

	for _, o := range slateTx.Body.Outputs {
		e := t.addSurjectionProof(&o, slateTx.Body.Inputs, senderSlate.Asset)
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

	walletTx = SavedTransaction{
		Transaction: ledgerTx,
		Status:      TransactionUnconfirmed,
	}

	return
}

func (t *Wallet) newOutput(
	value uint64,
	features ledger.OutputFeatures,
	asset string,
	status OutputStatus,
	outputBlind []byte,
) (
	walletOutput *SavedOutput,
	sumBlinds []byte,
	err error,
) {
	var index uint32 = 0
	var blind []byte
	if outputBlind == nil {
		var secret [32]byte
		secret, index, err = t.newSecret()
		if err != nil {
			err = errors.Wrap(err, "cannot get newSecret")
			return nil, nil, err
		}
		blind = secret[:]
	} else {
		blind = outputBlind
	}

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

	if outputBlind != nil {
		walletOutput.Blind = new([32]byte)
		copy(walletOutput.Blind[:], blind[:32])
	}

	return
}

func (t *Wallet) pubKeyFromSecretKey(sk32 []byte) (*secp256k1.PublicKey, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(t.context, sk32)
	if res != 1 || pk == nil || err != nil {
		return nil, errors.Wrap(err, "cannot create pubKeyFromSecretKey")
	}

	return pk, nil
}

func (t *Wallet) sumPubKeys(
	pubkeys []*secp256k1.PublicKey,
) (
	sum *secp256k1.PublicKey,
	err error,
) {
	res, sum, err := secp256k1.EcPubkeyCombine(t.context, pubkeys)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot sum public keys")
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

	//outputAssetSeed := ledger.AssetSeed(asset)
	//fixedOutputTag, err = secp256k1.FixedAssetTagParse(outputAssetSeed)

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

		//assetSeed := ledger.AssetSeed(asset)
		//assetTag, e = secp256k1.FixedAssetTagParse(assetSeed)

		assetTag, e = secp256k1.FixedAssetTagFromHex(input.AssetTag)

		if e != nil {
			err = errors.Wrap(e, "cannot get assetTag")
			return
		}

		fixedInputTags = append(fixedInputTags, assetTag)

		//inputAssetSecret, e := t.secret(input.AssetIndex)
		//if e != nil {
		//	err = errors.Wrap(e, "cannot get inputAssetSecret")
		//	return
		//}
		//assetBlind := inputAssetSecret[:]

		assetBlind, e := hex.DecodeString(input.AssetBlind)
		if e != nil {
			err = errors.Wrap(e, "cannot get assetBlind")
			return
		}

		//assetGenerator, err = secp256k1.GeneratorGenerateBlinded(t.context, assetSeed, assetBlind)
		//if err != nil {
		//	return
		//}
		//ephemeralInputTags = append(ephemeralInputTags, *assetGenerator)

		ephemeralInputTags = append(ephemeralInputTags, assetGenerator)

		inputAssetBlinds = append(inputAssetBlinds, assetBlind)
	}

	//outputAssetSecret, e := t.secret(output.AssetIndex)
	//if e != nil {
	//	err = errors.Wrapf(e, "cannot get outputAssetSecret")
	//	return
	//}
	//outputAssetBlind := outputAssetSecret[:]
	//
	//ephemeralOutputTag, err = secp256k1.GeneratorGenerateBlinded(t.context, outputAssetSeed, outputAssetBlind[:])

	//if err != nil {
	//	return
	//}

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

	//proofBytes, err := secp256k1.SurjectionproofSerialize(t.context, proof)
	//if err != nil {
	//	return
	//}

	//output.AssetProof = hex.EncodeToString(proofBytes)

	output.AssetProof = proof.String()

	return nil
}
