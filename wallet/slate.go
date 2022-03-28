package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-mimblewimble/uuid"
	"github.com/olegabu/go-secp256k1-zkp"
)

func (t *Wallet) NewSlate(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []SavedOutput,
	receiveAmount uint64,
	receiveAsset string,
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
		receiveAsset)
	if err != nil {
		err = fmt.Errorf("%w: cannot create slateInputs and walletOutputs", err)
		return
	}

	// generate secret nonce
	nonce, err := t.nonce()
	if err != nil {
		err = fmt.Errorf("%w: cannot get nonce", err)
		return
	}

	// generate random kernel offset
	kernelOffset, err := t.nonce()
	if err != nil {
		err = fmt.Errorf("%w: cannot get nonce for kernelOffset", err)
		return
	}

	// subtract kernel offset from blinding excess
	sumBlinds, err := secp256k1.BlindSum(t.context, [][]byte{blindExcess[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		err = fmt.Errorf("%w: cannot BlindSum", err)
		return
	}

	publicBlindExcess, err := t.pubKeyFromSecretKey(sumBlinds[:])
	if err != nil {
		err = fmt.Errorf("%w: cannot create publicBlindExcess", err)
		return
	}

	publicNonce, err := t.pubKeyFromSecretKey(nonce[:])
	if err != nil {
		err = fmt.Errorf("%w: cannot create publicNonce", err)
		return
	}

	var slateOutputs []SlateOutput
	for _, o := range walletOutputs {
		slateOutputs = append(slateOutputs, o.SlateOutput)
	}

	txidrand := secp256k1.Random256();

	slate := &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 2,
		Transaction: SlateTransaction{
			ID:     uuid.New(txidrand[:16]),
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
		err = fmt.Errorf("%w: cannot marshal slate to json", err)
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

		// re-create child secret key from its saved index and use it as this walletInput's blind
		secret, e := t.secret(walletInput.Index)
		if e != nil {
			err = fmt.Errorf("%w: cannot get secret for walletInput with key index %v", e, walletInput.Index)
			return
		}

		blind := secret[:]

		assetSecret, e := t.secret(walletInput.AssetIndex)
		if e != nil {
			err = fmt.Errorf("%w: cannot get assetSecret for walletInput with key index %v", e, walletInput.AssetIndex)
			return
		}

		assetBlind := assetSecret[:]

		// r + v*r_a
		valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(walletInput.Value, assetBlind, blind)
		if e != nil {
			err = fmt.Errorf("%w: cannot calculate valueAssetBlind", e)
			return
		}

		inputBlinds = append(inputBlinds, valueAssetBlind[:])

		slateInput := SlateInput{
			Input: ledger.Input{
				Features:    walletInput.Features,
				Commit:      walletInput.Commit,
				AssetCommit: walletInput.AssetCommit,
			},
			AssetTag: walletInput.AssetTag,
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
		changeOutput, changeBlind, e := t.newOutput(change, ledger.PlainOutput, asset, OutputUnconfirmed)
		if e != nil {
			err = fmt.Errorf("%w: cannot create change output", e)
			return
		}
		outputBlinds = append(outputBlinds, changeBlind)
		walletOutputs = append(walletOutputs, *changeOutput)
	}

	if receiveAmount > 0 {
		receiveOutput, receiveBlind, e := t.newOutput(receiveAmount, ledger.PlainOutput, receiveAsset, OutputUnconfirmed)
		if e != nil {
			err = fmt.Errorf("%w: cannot create receive output", e)
			return
		}
		outputBlinds = append(outputBlinds, receiveBlind)
		walletOutputs = append(walletOutputs, *receiveOutput)
	}

	// sum up slateInputs(-) and walletOutputs(+) blinding factors
	blindExcess, err = secp256k1.BlindSum(t.context, outputBlinds, inputBlinds)
	if err != nil {
		err = fmt.Errorf("%w: cannot create blinding excess sum", err)
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
		receiveAsset)
	if err != nil {
		err = fmt.Errorf("%w: cannot create slateInputs and walletOutputs", err)
		return
	}

	inSlate.Transaction.Body.Inputs = append(inSlate.Transaction.Body.Inputs, slateInputs...)

	// add responder output (receiver's in Send, payer's change in Invoice)
	for _, o := range walletOutputs {
		inSlate.Transaction.Body.Outputs = append(inSlate.Transaction.Body.Outputs, o.SlateOutput)
	}

	receiverPublicBlind, err := t.pubKeyFromSecretKey(blindExcess[:])
	if err != nil {
		err = fmt.Errorf("%w: cannot create publicBlind", err)
		return
	}

	// choose receiver nonce and calculate its public key
	receiverNonce, err := t.nonce()
	if err != nil {
		err = fmt.Errorf("%w: cannot get nonce", err)
		return
	}
	receiverPublicNonce, err := t.pubKeyFromSecretKey(receiverNonce[:])
	if err != nil {
		err = fmt.Errorf("%w: cannot create publicNonce", err)
		return
	}

	// parse out sender public blind and public nonce
	senderPublicBlind := t.context.PublicKeyFromHex(inSlate.ParticipantData[0].PublicBlindExcess)
	if senderPublicBlind == nil {
		err = fmt.Errorf("%w: cannot get senderPublicBlindExcess", err)
		return
	}
	senderPublicNonce := t.context.PublicKeyFromHex(inSlate.ParticipantData[0].PublicNonce)
	if senderPublicNonce == nil {
		err = fmt.Errorf("%w: cannot get senderPublicNonce", err)
		return
	}

	// Combine sender and receiver public blinds and nonces
	sumPublicBlinds, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = fmt.Errorf("%w: cannot get sumPublicBlindsBytes", err)
		return
	}
	sumPublicNonces, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = fmt.Errorf("%w: cannot get sumPublicNoncesBytes", err)
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
		err = fmt.Errorf("%w: cannot calculate receiver's partial signature", err)
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
		err = fmt.Errorf("%w: cannot marshal slate to json", err)
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
		err = fmt.Errorf("%w: amounts and assets in the response slate do not match; sent(%d %s %d %s) received(%d %s %d %s)", err,
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
		err = fmt.Errorf("%w: public keys mismatch, calculated values are not the same as loaded from responseSlate", err)
		return
	}

	receiverPublicBlind := t.context.PublicKeyFromHex(responseSlate.ParticipantData[1].PublicBlindExcess)
	receiverPublicNonce := t.context.PublicKeyFromHex(responseSlate.ParticipantData[1].PublicNonce)

	// combine sender and receiver public blinds and nonces
	sumPublicBlinds, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = fmt.Errorf("%w: cannot get sumPublicBlinds", err)
		return
	}
	sumPublicNonces, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = fmt.Errorf("%w: cannot get sumPublicNonces", err)
		return
	}

	// calculate message hash
	msg := ledger.KernelSignatureMessage(responseSlate.Transaction.Body.Kernels[0])

	// decode receiver's partial signature
	receiverPartSigBytes, err := hex.DecodeString(*responseSlate.ParticipantData[1].PartSig)
	if err != nil {
		err = fmt.Errorf("%w: cannot decode receiverPartSigBytes from hex", err)
		return
	}
	receiverPartSig, err := secp256k1.AggsigSignaturePartialParse(receiverPartSigBytes)
	if err != nil {
		err = fmt.Errorf("%w: cannot parse receiverPartialSig from bytes", err)
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
		err = fmt.Errorf("%w: cannot verify receiver partial signature", err)
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
		err = fmt.Errorf("%w: cannot calculate sender partial signature", err)
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
		err = fmt.Errorf("%w: cannot verify sender partial signature", err)
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
		err = fmt.Errorf("%w: cannot add sender and receiver partial signatures", err)
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
		err = fmt.Errorf("%w: cannot verify excess signature", err)
		return
	}

	slateTx := responseSlate.Transaction

	var inputCommitments, outputCommitments []*secp256k1.Commitment

	// collect input commitments
	for _, input := range slateTx.Body.Inputs {
		com, e := secp256k1.CommitmentFromString(input.Commit)
		if e != nil {
			err = fmt.Errorf("%w: error parsing input commitment", e)
			return
		}
		inputCommitments = append(inputCommitments, com)
	}

	// collect output commitments
	for _, output := range slateTx.Body.Outputs {
		com, e := secp256k1.CommitmentFromString(output.Commit)
		if e != nil {
			err = fmt.Errorf("%w: error parsing output commitment", e)
			return
		}
		outputCommitments = append(outputCommitments, com)
	}

	offsetBytes, err := hex.DecodeString(slateTx.Offset)
	if err != nil {
		err = fmt.Errorf("%w: cannot get offsetBytes", err)
		return
	}

	kernelExcess, err := ledger.CalculateExcess(
		t.context,
		inputCommitments,
		outputCommitments,
		offsetBytes,
		uint64(slateTx.Body.Kernels[0].Fee))
	if err != nil {
		err = fmt.Errorf("%w: cannot calculate kernel excess", err)
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(kernelExcess)
	if err != nil {
		err = fmt.Errorf("%w: excessPublicKey: CommitmentToPublicKey failed", err)
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
		err = fmt.Errorf("%w: AggsigVerifySingle failed to verify the finalSig with excessPublicKey", err)
		return
	}

	excessSig := secp256k1.AggsigSignatureSerialize(t.context, &finalSig)

	ledgerTx := ledger.Transaction{
		Offset: slateTx.Offset,
		ID:     slateTx.ID,
		Body: ledger.TransactionBody{
			Kernels: []ledger.TxKernel{
				{
					Excess:    secp256k1.CommitmentString(kernelExcess),
					ExcessSig: hex.EncodeToString(excessSig[:]),
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
			err = fmt.Errorf("%w: cannot addSurjectionProof", e)
			return
		}
		ledgerTx.Body.Outputs = append(ledgerTx.Body.Outputs, o.Output)
	}

	ledgerTxBytes, err = json.Marshal(ledgerTx)
	if err != nil {
		err = fmt.Errorf("%w: cannot marshal ledgerTx to json", err)
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
) (
	walletOutput *SavedOutput,
	sumBlinds []byte,
	err error,
) {
	secret, index, err := t.newSecret()
	if err != nil {
		err = fmt.Errorf("%w: cannot get newSecret", err)
		return
	}

	blind := secret[:]

	assetSecret, assetIndex, err := t.newSecret()
	if err != nil {
		err = fmt.Errorf("%w: cannot get newSecret", err)
		return
	}

	assetBlind := assetSecret[:]

	sumBlinds32, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind, blind)
	if e != nil {
		err = fmt.Errorf("%w: cannot calculate sumBlinds32", e)
	}
	sumBlinds = sumBlinds32[:]

	seed := ledger.AssetSeed(asset)

	assetTag, err := secp256k1.FixedAssetTagParse(seed)
	if err != nil {
		err = fmt.Errorf("%w: cannot get assetTag", err)
		return
	}

	assetCommitment, err := secp256k1.GeneratorGenerateBlinded(t.context, assetTag.Slice(), assetBlind)
	if err != nil {
		err = fmt.Errorf("%w: cannot create commitment to asset", err)
		return
	}

	// create commitment to value with asset specific generator
	commitment, err := secp256k1.Commit(
		t.context,
		blind,
		value,
		assetCommitment)
	if err != nil {
		err = fmt.Errorf("%w: cannot create commitment to value", err)
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
		err = fmt.Errorf("%w: cannot create bulletproof", err)
		return
	}

	walletOutput = &SavedOutput{
		SlateOutput: SlateOutput{
			Output: ledger.Output{
				Input: ledger.Input{
					Features:    features,
					Commit:      secp256k1.CommitmentString(commitment),
					AssetCommit: assetCommitment.String(),
				},
				Proof: hex.EncodeToString(proof),
			},
			AssetTag: assetTag.Hex(),
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

func (t *Wallet) pubKeyFromSecretKey(sk32 []byte) (*secp256k1.PublicKey, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(t.context, sk32)
	if res != 1 || pk == nil || err != nil {
		return nil, fmt.Errorf("%w: cannot create pubKeyFromSecretKey", err)
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
		return nil, fmt.Errorf("%w: cannot sum public keys", err)
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
			err = fmt.Errorf("%w: cannot get assetGenerator", e)
			return
		}

		//assetSeed := ledger.AssetSeed(asset)
		//assetTag, e = secp256k1.FixedAssetTagParse(assetSeed)

		assetTag, e = secp256k1.FixedAssetTagFromHex(input.AssetTag)

		if e != nil {
			err = fmt.Errorf("%w: cannot get assetTag", e)
			return
		}

		fixedInputTags = append(fixedInputTags, assetTag)

		//inputAssetSecret, e := t.secret(input.AssetIndex)
		//if e != nil {
		//	err = fmt.Errorf("%w: cannot get inputAssetSecret", e)
		//	return
		//}
		//assetBlind := inputAssetSecret[:]

		assetBlind, e := hex.DecodeString(input.AssetBlind)
		if e != nil {
			err = fmt.Errorf("%w: cannot get assetBlind", e)
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
	//	err = fmt.Errorf("%w: cannot get outputAssetSecret", e)
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
