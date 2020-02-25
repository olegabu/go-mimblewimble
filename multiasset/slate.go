package multiasset

import (
	"encoding/hex"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func CreateSlate(purchases []AssetBalance, expenses []AssetBalance, fee AssetBalance) (slate Slate) {
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
			PaymentProof:    nil,
		},
		Status: wallet.Slatecreated,
	}
	return
}
func (slate *Slate) Process(
	context *secp256k1.Context,
	walletInputs []PrivateOutput, // the tokens you have
	purchases []AssetBalance, // the tokens you buy
	expenses []AssetBalance) ( //the tokens  you spend
	//publicSlate PublicSlate,
	privateOutputs []PrivateOutput,
	err error,
) {
	// create a local context object if it's not provided in parameters
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

	//create change privateOutputs with token commitment and surjection proof
	var spentInputs []SlateInput

	var changeValues map[Asset]uint64

	spentInputs, inputBlinds, changeValues, err = calculateOutputValues(slate.Fee, walletInputs, expenses)
	if err != nil {
		return
	}

	var slateOutputs []SlateOutput

	for asset, changeValue := range changeValues {

		privateOutput, slateOutput, err = createOutput(context, AssetBalance{
			Asset:  asset,
			Amount: changeValue,
		})

		if err != nil {
			return
		}
		slateOutputs = append(slateOutputs, slateOutput)
		privateOutputs = append(privateOutputs, privateOutput)
		outputBlinds = append(outputBlinds, privateOutput.ValueBlind[:])
	}

	//create purchase privateOutputs with token commitment. We can't create
	for _, purchase := range purchases {
		privateOutput, slateOutput, err = createOutput(context, purchase)
		if err != nil {
			return
		}
		privateOutputs = append(privateOutputs, privateOutput)
	}

	var publicBlindExcess *secp256k1.PublicKey
	var blindExcess1 [32]byte

	blindExcess1, err = secp256k1.BlindSum(context, outputBlinds, inputBlinds)
	if err != nil {
		return
	}

	// generate random kernel offset
	var nonce [32]byte
	nonce, err = wallet.Secret(context)

	publicNonce, _ := wallet.PubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return
	}
	var pubNonceBytes []byte
	_, pubNonceBytes, err = secp256k1.EcPubkeySerialize(context, publicNonce, secp256k1.EcCompressed)
	pubNonceString := hex.EncodeToString(pubNonceBytes)

	switch slate.Status {
	case wallet.Slatecreated:

		var kernelOffset [32]byte
		kernelOffset, err = wallet.Secret(context)
		if err != nil {
			return
		}

		var blindExcess [32]byte
		blindExcess, err = secp256k1.BlindSum(context, [][]byte{blindExcess1[:]}, [][]byte{kernelOffset[:]})
		if err != nil {
			return
		}

		publicBlindExcess, err = wallet.PubKeyFromSecretKey(context, blindExcess[:])
		if err != nil {
			return
		}

		transaction := &Transaction{
			Offset: hex.EncodeToString(kernelOffset[:]),
			Body: TransactionBody{
				Inputs:  spentInputs,
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

	case wallet.SlateSent:
		//generate secret nonce and calculate its public key

		var excessBytes, otherPublicBlindBytes []byte
		transaction := slate.Transaction
		kernel := transaction.Body.Kernels[0]

		// Combine public blinds and nonces
		var myPublicBlind, otherPublicBlind, kernelExcess *secp256k1.PublicKey

		_, myPublicBlind, err = secp256k1.EcPubkeyCreate(context, blindExcess1[:])
		if err != nil {
			return
		}

		otherPublicBlindBytes, err = hex.DecodeString(slate.ParticipantData[0].PublicBlindExcess)
		if err != nil {
			return
		}

		_, otherPublicBlind, err = secp256k1.EcPubkeyParse(context, otherPublicBlindBytes)
		if err != nil {
			return
		}

		_, kernelExcess, err = secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{myPublicBlind, otherPublicBlind})
		if err != nil {
			return
		}

		_, excessBytes, err = secp256k1.EcPubkeySerialize(context, kernelExcess, secp256k1.EcCompressed)
		if err != nil {
			return
		}

		var otherPubNonceBytes []byte
		otherPubNonceBytes, err = hex.DecodeString(slate.ParticipantData[0].PublicNonce)
		_, otherPubNonce, _ := secp256k1.EcPubkeyParse(context, otherPubNonceBytes)

		var pubNonceSum *secp256k1.PublicKey
		_, pubNonceSum, err = secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{otherPubNonce, publicNonce})
		if err != nil {
			return
		}
		kernel.Excess = hex.EncodeToString(excessBytes)

		var sig secp256k1.AggsigSignaturePartial
		sig, err = secp256k1.AggsigSignPartial(context, blindExcess1[:], nonce[:], pubNonceSum, kernelExcess, []byte{})
		if err != nil {
			return
		}

		sigBytes := secp256k1.AggsigSignaturePartialSerialize(&sig)
		partSig := hex.EncodeToString(sigBytes[:])

		participantData := &libwallet.ParticipantData{
			ID:                1,
			PublicBlindExcess: myPublicBlind.Hex(context),
			PublicNonce:       pubNonceString,
			PartSig:           &partSig,
			Message:           nil,
			MessageSig:        nil,
		}

		slate.ParticipantData = append(slate.ParticipantData, *participantData)
		transaction.Body.Outputs = append(transaction.Body.Outputs, slateOutputs...)
		transaction.Body.Inputs = append(transaction.Body.Inputs, spentInputs...)
		slate.Status = wallet.SlateResponded

	}
	return
}

func (slate *Slate) Finalize(context *secp256k1.Context) (err error) {
	if slate.Status != wallet.SlateResponded {
		err = errors.New("wrong slate status")
		return
	}
	transactionBody := slate.Transaction.Body
	for _, output := range transactionBody.Outputs {
		_ = (&output).addSurjectionProof(context, transactionBody.Inputs)
	}
	return
}

func (output *SlateOutput) addSurjectionProof(context *secp256k1.Context, inputs []SlateInput) (err error) {
	/*
		The surjection proof proves that for a particular output there is at least one corresponding input with the same asset id.
		The sender must create both change outputs and outputs for tokens she wishes to acquire as a result of this transaction,
		because she must generate blinding factors for them to be available for later spending.
		Furthermore it is the sender who also generates surjection proof for the tokens she pays with (aka expenses)
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
