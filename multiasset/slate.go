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

func CreateSlate(
	context *secp256k1.Context,
	fee AssetBalance,
	walletInputs []PrivateOutput, // the tokens you have
	purchases []AssetBalance, // the tokens you buy
	expenses []AssetBalance) ( //the tokens  you spend
	slate Slate,
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
	var spentInputs []Input

	var changeValues map[Asset]uint64

	spentInputs, inputBlinds, changeValues, err = calculateOutputValues(fee, walletInputs, expenses)
	if err != nil {
		return
	}

	var slateOutputs []SlateOutput

	for asset, changeValue := range changeValues {

		privateOutput, slateOutput, err = createOutput(context, AssetBalance{
			asset:  asset,
			amount: changeValue,
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

	switch slate.Status {
	case wallet.Slatecreated:

		amount := append(expenses, purchases...)
		var kernelOffset [32]byte
		kernelOffset, err = wallet.Secret(context)
		if err != nil {
			return
		}

		blindExcess, err := secp256k1.BlindSum(context, [][]byte{blindExcess1[:]}, [][]byte{kernelOffset[:]})
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
					Fee:        fee,
					LockHeight: 0,
					Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
					ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				}},
			},
			ID: uuid.UUID{},
		}

		var pubNonceBytes []byte
		_, pubNonceBytes, err = secp256k1.EcPubkeySerialize(context, publicNonce, secp256k1.EcCompressed)
		slate = Slate{
			publicSlate: publicSlate{
				VersionInfo: libwallet.VersionCompatInfo{
					Version:            0,
					OrigVersion:        0,
					BlockHeaderVersion: 0,
				},
				NumParticipants: 2,
				ID:              uuid.New(),
				Transaction:     *transaction,
				Amount:          amount,
				Fee:             fee,
				Height:          0,
				LockHeight:      0,
				TTLCutoffHeight: nil,
				ParticipantData: []libwallet.ParticipantData{{
					ID:                0,
					PublicBlindExcess: publicBlindExcess.Hex(context),
					PublicNonce:       hex.EncodeToString(pubNonceBytes),
					PartSig:           nil,
					Message:           nil,
					MessageSig:        nil,
				}},
				PaymentProof: nil,
			},
			Status: wallet.SlateSent,
		}
		return
	case wallet.SlateSent:
		//generate secret nonce and calculate its public key

		var serializedExcess []byte
		transaction := slate.Transaction
		kernel := transaction.Body.Kernels[0]

		// Combine public blinds and nonces
		var senderPublicBlind, receiverPublicBlind, sumPublicBlinds *secp256k1.PublicKey
		_, sumPublicBlinds, err = secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
		if err != nil {
			return
		}
		_, serializedExcess, err = secp256k1.EcPubkeySerialize(context, sumPublicBlinds, secp256k1.EcCompressed)
		if err != nil {
			return
		}

		var senderPublicNonceBytes []byte
		senderPublicNonceBytes, err = hex.DecodeString(slate.ParticipantData[0].PublicNonce)
		_, senderPublicNonce, _ := secp256k1.EcPubkeyParse(context, senderPublicNonceBytes)

		_, sumPublicNonces, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicNonce, publicNonce})
		if err != nil {
			return
		}
		kernel.Excess = hex.EncodeToString(serializedExcess)

		_, _ = secp256k1.AggsigSignPartial(context, blindExcess1[:], nonce[:], sumPublicNonces, sumPublicBlinds, []byte{})

	}
	if slate.Status == wallet.Slatecreated {

	}

	// Subtract kernel offset from blinding excess sum

	// Create public curve points from blindExcess
	//var publicNonce [32]byte
	//publicNonce, err = wallet.PubKeyFromSecretKey(context, nonce[:])
	//if err != nil {
	//	return
	//}
	//copy(slate.SenderNonce[:], nonce[:])
	//copy(slate.SumSenderBlinds[:], blindExcess[:])
	//slate.Status = SlateSent

	return
}

func (slate *Slate) receive(context *secp256k1.Context,
	fee AssetBalance,
	walletInputs []PrivateOutput, // the assets Alice owns hence pays with
	purchases []AssetBalance, // the assets Alice buys
	spends []AssetBalance) ( //the assets Alice pays with
	slateBytes []byte,
	outputs []PrivateOutput,

	err error,
) {

	return nil, nil, nil
}
func (slate *Slate) generateSurjectionProof(context *secp256k1.Context, inputs []SlateOutput, output SlateOutput) (proof *secp256k1.Surjectionproof, err error) {
	/*
		The surjection proof proves that for a particular output there is at least one corresponding input with the same asset id.
		The sender must create both change outputs and outputs which she wishes to acquire as a result of this transaction,
		because she must generate blinding factors for them to be available for later spending.
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

	_, proof, inputIndex, err = secp256k1.SurjectionproofAllocateInitialized(context, fixedInputAssetTags, 1, fixedOutputAssetTag, 10, seed32[:])

	if len(inputBlindingKeys) < inputIndex {
		return nil, errors.Wrap(nil, "input not found")
	}
	err = secp256k1.SurjectionproofGenerate(context, proof, ephemeralInputTags[:], *ephemeralOutputTag, inputIndex, inputBlindingKeys[inputIndex][:], outputAssetBlind[:])
	if err != nil {
		return
	}

	return proof, nil

}
