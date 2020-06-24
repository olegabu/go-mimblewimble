package multiasset

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	util "github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (o *PrivateOutput) tweakedExcess() (excess []byte, err error) {

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	valueBytes := make([]byte, 32)
	assetBlind, _ := hex.DecodeString(o.AssetBlind)
	binary.LittleEndian.PutUint64(valueBytes, o.Value)

	var result int

	result, err = secp256k1.EcPrivkeyTweakMul(ctx, assetBlind, valueBytes)

	if result != 1 || err != nil {
		err = errors.New(fmt.Sprintf("EcPrivkeyTweakMul failed: %v", err))
		return
	}

	result, err = secp256k1.EcPrivkeyTweakAdd(ctx, assetBlind, o.ValueBlind[:])

	return
}
func (w *Wallet) CreateSlate(purchases []AssetBalance, expenses []AssetBalance, fee AssetBalance) (slate Slate, privateOutputs []PrivateOutput,
	err error) {
	amount := append(expenses, purchases...)
	slate = Slate{
		PublicSlate: PublicSlate{
			VersionInfo: libwallet.VersionCompatInfo{
				Version:            0,
				OrigVersion:        0,
				BlockHeaderVersion: 0,
			},
			NumParticipants: 2,
			ID:              uuid.New(),
			Transaction:     Transaction{},
			Amount:          amount,
			Fee:             fee,
			Height:          0,
			LockHeight:      0,
			TTLCutoffHeight: nil,
			ParticipantData: []libwallet.ParticipantData{},
			//PaymentProof:    nil,
		},
		Status: util.Slatecreated,
	}

	var privateOutput PrivateOutput
	var slateOutput SlateOutput

	var outputBlinds, inputBlinds [][]byte

	var tweakedExcess []byte

	context := w.context

	var spentInputs []PrivateOutput

	var changeValues map[Asset]uint64

	if slate.Status == util.SlateSent {
		fee.Value = 0
	}

	spentInputs, changeValues, err = w.calculateOutputValues(fee, expenses)
	if err != nil {
		return
	}
	var spentInputsPublicInfo []SlateInput

	for _, input := range spentInputs {
		spentInputsPublicInfo = append(spentInputsPublicInfo, SlateInput{
			Input:      input.SlateOutput.Input,
			Asset:      input.Asset,
			AssetBlind: input.AssetBlind,
		})
		tweakedExcess, err = input.tweakedExcess()
		inputBlinds = append(inputBlinds, tweakedExcess)
	}

	var slateOutputs []SlateOutput

	for asset, changeValue := range changeValues {

		privateOutput, err = w.createOutput(AssetBalance{
			Asset: asset,
			Value: changeValue,
		})

		if err != nil {
			return
		}
		slateOutputs = append(slateOutputs, privateOutput.SlateOutput)
		privateOutputs = append(privateOutputs, privateOutput)

		tweakedExcess, err = privateOutput.tweakedExcess()
		if err != nil {
			return
		}
		outputBlinds = append(outputBlinds, tweakedExcess)
	}

	//create purchase privateOutputs with token commitment.
	for _, purchase := range purchases {
		privateOutput, err = w.createOutput(purchase)
		if err != nil {
			return
		}
		privateOutputs = append(privateOutputs, privateOutput)
		slateOutputs = append(slateOutputs, slateOutput)
	}

	var publicBlindExcess *secp256k1.PublicKey
	var blindExcess1 [32]byte

	blindExcess1, err = secp256k1.BlindSum(context, outputBlinds, inputBlinds)
	if err != nil {
		return
	}

	var nonce [32]byte
	nonce, err = util.Secret(context)

	publicNonce, _ := util.PubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return
	}
	var pubNonceBytes []byte
	_, pubNonceBytes, err = secp256k1.EcPubkeySerialize(context, publicNonce, secp256k1.EcCompressed)
	pubNonceString := hex.EncodeToString(pubNonceBytes)

	// generate random kernel offset
	var kernelOffset [32]byte
	kernelOffset, err = util.Secret(context)
	if err != nil {
		return
	}

	var blindExcess [32]byte
	blindExcess, err = secp256k1.BlindSum(context, [][]byte{blindExcess1[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		return
	}

	publicBlindExcess, err = util.PubKeyFromSecretKey(context, blindExcess[:])
	if err != nil {
		return
	}

	transaction := &Transaction{
		Offset: hex.EncodeToString(kernelOffset[:]),
		Body: TransactionBody{
			Inputs:  spentInputsPublicInfo,
			Outputs: slateOutputs,
			Kernels: []TxKernel{{
				Features:   core.PlainKernel,
				Fee:        slate.Fee,
				LockHeight: 0,
				Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
				ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			}},
		},
		ID: uuid.UUID{},
	}

	slate.ParticipantData = append(slate.ParticipantData, libwallet.ParticipantData{
		ID:                0,
		PublicBlindExcess: publicBlindExcess.Hex(context),
		PublicNonce:       pubNonceString,
		PartSig:           nil,
		Message:           nil,
		MessageSig:        nil,
	})
	slate.Transaction = *transaction
	slate.Status = util.SlateSent
	return
}
func (slate *Slate) Process(
	context *secp256k1.Context,
	walletInputs []PrivateOutput, // the tokens you have
	purchases []AssetBalance, // the tokens you buy
	expenses []AssetBalance) ( //the tokens  you spend
	publicSlate PublicSlate,
	privateOutputs []PrivateOutput,
	err error,
) {
	/*
		This is a common part of slate processing both for Alice and Bob.
		Since the transaction is bidirectional, both participant do the same stuff:
		1. Check purchases and expenses against available assets
		2. Generate outputs for change and purchases
	*/
	if context == nil {
		if context, err = secp256k1.ContextCreate(secp256k1.ContextBoth); err != nil {
			err = errors.Wrap(err, "ContextCreate failed")
			return
		}
		defer secp256k1.ContextDestroy(context)
	}

	var privateOutput PrivateOutput
	var slateOutput SlateOutput

	var outputBlinds, inputBlinds [][]byte

	var spentInputs []PrivateOutput

	var changeValues map[Asset]uint64

	fee := slate.Fee
	if slate.Status == util.SlateSent {
		fee.Value = 0
	}
	w := Wallet{inputs: walletInputs, context: context}
	spentInputs, changeValues, err = w.calculateOutputValues(fee, expenses)
	var tweakedExcess []byte
	var spentInputsPublicInfo []SlateInput
	for _, input := range spentInputs {
		spentInputsPublicInfo = append(spentInputsPublicInfo, SlateInput{
			Input:      input.SlateOutput.Input,
			Asset:      input.Asset,
			AssetBlind: input.AssetBlind,
		})
		tweakedExcess, err = input.tweakedExcess()
		inputBlinds = append(inputBlinds, tweakedExcess)
	}

	if err != nil {
		return
	}

	var slateOutputs []SlateOutput

	for asset, changeValue := range changeValues {

		privateOutput, err = w.createOutput(AssetBalance{
			Asset: asset,
			Value: changeValue,
		})

		if err != nil {
			return
		}

		tweakedExcess, err = privateOutput.tweakedExcess()

		slateOutputs = append(slateOutputs, slateOutput)
		privateOutputs = append(privateOutputs, privateOutput)
		outputBlinds = append(outputBlinds, tweakedExcess)
	}

	//create purchase privateOutputs with token commitment.
	for _, purchase := range purchases {
		privateOutput, err = w.createOutput(purchase)
		if err != nil {
			return
		}
		privateOutputs = append(privateOutputs, privateOutput)
		slateOutputs = append(slateOutputs, slateOutput)
	}

	//var publicBlindExcess *secp256k1.PublicKey
	var blindExcess1 [32]byte

	blindExcess1, err = secp256k1.BlindSum(context, outputBlinds, inputBlinds)
	if err != nil {
		return
	}

	// generate random kernel offset
	var nonce [32]byte
	nonce, err = util.Secret(context)

	publicNonce, _ := util.PubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return
	}
	var pubNonceBytes []byte
	_, pubNonceBytes, err = secp256k1.EcPubkeySerialize(context, publicNonce, secp256k1.EcCompressed)
	pubNonceString := hex.EncodeToString(pubNonceBytes)

	/*
		Bob receives slate and
		1. Parses data from Alice: public nonce ( Ka = ka * G), public blinded excess ( sum(Ra) = sum (ra*G))
		2. Calculates so called "overage" ( commitment to fee value) with respect to the fee token type
		3. Generates his signature
	*/

	var excessBytes, alicePubBlindExcessBytes []byte
	transaction := slate.Transaction
	kernel := transaction.Body.Kernels[0]

	// Combine public blinds and nonces
	var bobPublicBlindExcess, alicePublicBlindExcess, kernelExcess *secp256k1.PublicKey

	_, bobPublicBlindExcess, err = secp256k1.EcPubkeyCreate(context, blindExcess1[:])
	if err != nil {
		return
	}

	alicePubBlindExcessBytes, err = hex.DecodeString(slate.ParticipantData[0].PublicBlindExcess)
	if err != nil {
		return
	}

	_, alicePublicBlindExcess, err = secp256k1.EcPubkeyParse(context, alicePubBlindExcessBytes)
	if err != nil {
		return
	}

	//feeGenerator, _ := secp256k1.GeneratorGenerate(context, slate.Fee.Asset.seed()) //TODO: use when validating transaction
	//var zeroBlind [32]byte
	//feeExcess, _ := secp256k1.Commit(context, zeroBlind[:], slate.Fee.Value, feeGenerator, &secp256k1.GeneratorG)

	_, kernelExcess, err = secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{bobPublicBlindExcess, alicePublicBlindExcess})
	if err != nil {
		return
	}

	_, excessBytes, err = secp256k1.EcPubkeySerialize(context, kernelExcess, secp256k1.EcCompressed)
	if err != nil {
		return
	}

	var alicePubNonceBytes []byte
	alicePubNonceBytes, err = hex.DecodeString(slate.ParticipantData[0].PublicNonce)
	_, alicePubNonce, _ := secp256k1.EcPubkeyParse(context, alicePubNonceBytes)

	var pubNonceSum *secp256k1.PublicKey
	_, pubNonceSum, err = secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{alicePubNonce, publicNonce})
	if err != nil {
		return
	}
	kernel.Excess = hex.EncodeToString(excessBytes)

	var sig secp256k1.AggsigSignaturePartial

	msg := kernel.sigMsg()
	sig, err = secp256k1.AggsigSignPartial(context, blindExcess1[:], nonce[:], pubNonceSum, kernelExcess, msg)
	if err != nil {
		return
	}

	sigBytes := secp256k1.AggsigSignaturePartialSerialize(&sig)
	partSig := hex.EncodeToString(sigBytes[:])

	participantData := &libwallet.ParticipantData{
		ID:                1,
		PublicBlindExcess: bobPublicBlindExcess.Hex(context),
		PublicNonce:       pubNonceString,
		PartSig:           &partSig,
		Message:           nil,
		MessageSig:        nil,
	}

	slate.ParticipantData = append(slate.ParticipantData, *participantData)
	transaction.Body.Outputs = append(transaction.Body.Outputs, slateOutputs...)
	transaction.Body.Inputs = append(transaction.Body.Inputs, spentInputsPublicInfo...)
	slate.Status = util.SlateResponded
	//TODO: store the slate with private data
	publicSlate = slate.PublicSlate // to be shared with the counterparty

	return
}

func (slate *Slate) Finalize(context *secp256k1.Context) (tx Transaction, err error) {
	if slate.Status != util.SlateResponded {
		err = errors.New("wrong slate status")
		return
	}
	transactionBody := slate.Transaction.Body
	for _, output := range transactionBody.Outputs {
		_ = (&output).addSurjectionProof(context, transactionBody.Inputs)
	}

	bobPubNonce := context.PublicKeyFromHex(slate.ParticipantData[1].PublicNonce) //Kb
	//bobPubBlindExcess := context.PublicKeyFromHex(slate.ParticipantData[1].PublicBlindExcess)//Rb
	bobPartialSigBytes, _ := hex.DecodeString(*slate.ParticipantData[1].PartSig)
	bobPartialSig, _ := secp256k1.AggsigSignaturePartialParse(bobPartialSigBytes)

	//
	alicePubNonce := context.PublicKeyFromHex(slate.ParticipantData[0].PublicNonce) //Ka
	//alicePubBlindExcess := context.PublicKeyFromHex(slate.ParticipantData[0].PublicBlindExcess)//Ra

	alicePrivateNonce := slate.Nonce  //ka
	alicePrivateExcess := slate.SkSum //ra

	var pubNonceSum *secp256k1.PublicKey
	_, pubNonceSum, err = secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{alicePubNonce, bobPubNonce})
	if err != nil {
		return
	}
	kernel := slate.Transaction.Body.Kernels[0]
	excessBytes, _ := hex.DecodeString(kernel.Excess)
	_, excess, _ := secp256k1.EcPubkeyParse(context, excessBytes)

	var aliceSig secp256k1.AggsigSignaturePartial
	//msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])
	msg := kernel.sigMsg()
	aliceSig, err = secp256k1.AggsigSignPartial(context, alicePrivateExcess[:], alicePrivateNonce[:], pubNonceSum, excess, msg)
	if err != nil {
		return
	}

	finalSig, err := secp256k1.AggsigAddSignaturesSingle(
		context,
		[]*secp256k1.AggsigSignaturePartial{
			&aliceSig,
			&bobPartialSig,
		},
		pubNonceSum)
	if err != nil {
		return
	}

	aggsigSignatureSerialize := secp256k1.AggsigSignatureSerialize(context, &finalSig)
	kernel.ExcessSig = hex.EncodeToString(aggsigSignatureSerialize[:])

	//sigBytes := secp256k1.AggsigSignaturePartialSerialize(&sig)
	//partSig := hex.EncodeToString(sigBytes[:])

	return
}

func (output *SlateOutput) addSurjectionProof(context *secp256k1.Context, inputs []SlateInput) (err error) {
	/*
			The surjection proof proves that for a particular output there is at least one corresponding input with the same asset id.
			The Alice creates all of the proofs:
			1. her change outputs
			2. the outputs she acquires ("purchases" from Alice's perspective, i.e. spent by Bob)
			3. the outputs created by Bob ("expenses" from Alice's perspective, i.e. spent by Alice)
			4. the Bob's change
		This is done as a part of transaction finalization due to the fact that one needs all of the transaction inputs asset blinding factors to generate a proof (i.e. each output gets a proof against the whole set of inputs)
	*/
	var fixedInputAssetTags []secp256k1.FixedAssetTag

	var inputIndex int
	var inputBlindingKeys [][]byte
	asset := output.Asset
	var fixedOutputAssetTag *secp256k1.FixedAssetTag
	var ephemeralInputTags []secp256k1.Generator
	var ephemeralOutputTag *secp256k1.Generator

	fixedOutputAssetTag, err = secp256k1.FixedAssetTagParse(asset.seed())

	for _, input := range inputs {
		var fixedAssetTag *secp256k1.FixedAssetTag
		var tokenCommitment *secp256k1.Generator
		fixedAssetTag, err = secp256k1.FixedAssetTagParse(input.Asset.seed())

		if err != nil {
			return
		}
		fixedInputAssetTags = append(fixedInputAssetTags, *fixedAssetTag)

		var inputAssetBlind []byte
		inputAssetBlind, err = hex.DecodeString(input.AssetBlind)
		if err != nil {
			return
		}
		tokenCommitment, err = secp256k1.GeneratorGenerateBlinded(context, input.Asset.seed(), inputAssetBlind)
		if err != nil {
			return
		}
		ephemeralInputTags = append(ephemeralInputTags, *tokenCommitment)

		inputBlindingKeys = append(inputBlindingKeys, inputAssetBlind)
	}

	var outputAssetBlind []byte
	outputAssetBlind, err = hex.DecodeString(output.AssetBlind)
	ephemeralOutputTag, err = secp256k1.GeneratorGenerateBlinded(context, output.Asset.seed(), outputAssetBlind[:])

	if err != nil {
		return
	}

	seed32 := secp256k1.Random256()
	var proof *secp256k1.Surjectionproof
	_, proof, inputIndex, err = secp256k1.SurjectionproofAllocateInitialized(context, fixedInputAssetTags, 1, fixedOutputAssetTag, 10, seed32[:])

	if len(inputBlindingKeys) < inputIndex {
		return errors.Wrap(nil, "input not found")
	}
	err = secp256k1.SurjectionproofGenerate(context, proof, ephemeralInputTags[:], *ephemeralOutputTag, inputIndex, inputBlindingKeys[inputIndex][:], outputAssetBlind[:])
	if err != nil {
		return
	}

	var proofBytes []byte
	proofBytes, err = secp256k1.SurjectionproofSerialize(context, proof)
	(*output).SurjectionProof = hex.EncodeToString(proofBytes)
	return nil

}
