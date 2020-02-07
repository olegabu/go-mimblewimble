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
	walletInputs []privateOutput,
	purchases []AssetBalance,
	offers []AssetBalance) (
	slateBytes []byte,
	outputs []privateOutput,
	senderSlate SenderSlate,
	err error,
) {
	// create a local context object if it's not provided in parameters
	if context == nil {
		if context, err = secp256k1.ContextCreate(secp256k1.ContextBoth); err != nil {
			return nil, nil, SenderSlate{}, errors.Wrap(err, "ContextCreate failed")
		}
		defer secp256k1.ContextDestroy(context)
	}

	offerBalance := make(map[string]uint64)
	inputsByAsset := make(map[string][]privateOutput)
	inputsById := make(map[string]privateOutput)

	offerBalance[fee.asset.name] += fee.amount

	for _, offer := range offers {
		offerBalance[offer.asset.name] += offer.amount
	}

	myBalance := make(map[string]uint64)
	for _, input := range walletInputs {
		myBalance[input.Asset.name] += input.Value
		inputsByAsset[input.Asset.name] = append(inputsByAsset[input.Asset.name], input)
		inputsById[input.Commit.ValueCommitment] = input
	}

	for assetId, value := range offerBalance {
		if myBalance[assetId] < value {
			err = errors.New("insufficient funds")
			return
		}
	}

	inputsToBeSpent := make(map[string]privateOutput)

	for _, offer := range offers {
		remainder := offer.amount

		for _, input := range inputsByAsset[offer.asset.name] {

			if input.Value == 0 {
				continue
			}

			inputsToBeSpent[input.Commit.ValueCommitment] = input

			if input.Value-remainder > 0 {
				input.Value = input.Value - remainder
				remainder = 0
				break
			}

			input.Value = 0
			remainder = remainder - input.Value

		}

	}

	changeAmountsToBeCreated := make(map[Asset]uint64)
	for id, input := range inputsToBeSpent {
		if inputsById[id].Value > input.Value {
			changeAmountsToBeCreated[input.Asset] = inputsById[id].Value - input.Value
		}
	}

	//output := privateOutput{}
	var output privateOutput
	var outputBlinds, inputBlinds [][]byte
	for _, input := range walletInputs {
		inputBlinds = append(inputBlinds, input.ValueBlind[:])
	}
	for asset, changeValue := range changeAmountsToBeCreated {

		output, err = createOutput(context, asset, changeValue, walletInputs)
		if err != nil {
			return
		}
		outputs = append(outputs, output)
		outputBlinds = append(outputBlinds, output.ValueBlind[:])
	}

	for _, purchase := range purchases {
		output, err = createOutput(context, purchase.asset, purchase.amount, walletInputs)
		if err != nil {
			return
		}
		outputs = append(outputs, output)
	}

	var nonce, kernelOffset [32]byte
	var publicBlindExcess, publicNonce *secp256k1.PublicKey
	//nonce, err = wallet.Secret(context)

	blindExcess1, err := secp256k1.BlindSum(context, outputBlinds, inputBlinds)
	if err != nil {
		return nil, nil, SenderSlate{}, errors.Wrap(err, "cannot create blinding excess sum")
	}

	// generate secret nonce and calculate its public key
	nonce, err = wallet.Secret(context)
	if err != nil {
		return nil, nil, SenderSlate{}, errors.Wrap(err, "cannot get secret for nonce")
	}

	// generate random kernel offset
	kernelOffset, err = wallet.Secret(context)
	if err != nil {
		return nil, nil, SenderSlate{}, errors.Wrap(err, "cannot get random offset")
	}

	// Subtract kernel offset from blinding excess sum
	blindExcess, err := secp256k1.BlindSum(context, [][]byte{blindExcess1[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		return nil, nil, SenderSlate{}, errors.Wrap(err, "cannot get offset for blind")
	}

	publicBlindExcess, err = wallet.PubKeyFromSecretKey(context, blindExcess[:])
	if err != nil {
		return nil, nil, SenderSlate{}, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	// Create public curve points from blindExcess
	publicNonce, err = wallet.PubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return nil, nil, SenderSlate{}, errors.Wrap(err, "cannot create publicNonce")
	}

	senderSlate = SenderSlate{
		Slate: Slate{
			publicSlate: publicSlate{
				VersionInfo: libwallet.VersionCompatInfo{
					Version:            0,
					OrigVersion:        0,
					BlockHeaderVersion: 0,
				},
				NumParticipants: 2,
				ID:              uuid.New(),
				Transaction: LedgerTransaction{
					Offset: hex.EncodeToString(kernelOffset[:]),
					Body: TransactionBody{
						Inputs:  nil,
						Outputs: nil,
						Kernels: []TxKernel{{
							Features:   core.PlainKernel,
							Fee:        fee,
							LockHeight: 0,
							Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
							ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
						}},
					},
					ID: uuid.New(),
				},
				Amount:          offers,
				Fee:             fee,
				Height:          0,
				LockHeight:      0,
				TTLCutoffHeight: nil,
				ParticipantData: []libwallet.ParticipantData{{
					ID:                0,
					PublicBlindExcess: publicBlindExcess.Hex(context),
					PublicNonce:       publicNonce.Hex(context),
					PartSig:           nil,
					Message:           nil,
					MessageSig:        nil,
				}},
				PaymentProof: nil,
			},
			Status: 0,
		},
		SumSenderBlinds: [32]byte{},
		SenderNonce:     nonce,
	}
	return
}

func createOutput(context *secp256k1.Context, asset Asset, value uint64, inputs []privateOutput) (output privateOutput, err error) {
	valueBlind, _ := wallet.Secret(context)
	assetBlind, _ := wallet.Secret(context)

	H, err := secp256k1.GeneratorGenerateBlinded(context, asset.Id[:], assetBlind[:])
	assetCommitment, _ := secp256k1.Commit(context, assetBlind[:], 1, H, &secp256k1.GeneratorG)
	valueCommitment, _ := secp256k1.Commit(context, valueBlind[:], value, H, &secp256k1.GeneratorG)
	changeCommitment := Commitment{
		ValueCommitment: valueCommitment.Hex(context),
		AssetCommitment: assetCommitment.Hex(context),
	}

	proof, err := secp256k1.BulletproofRangeproofProveSingle(
		context,
		nil,
		nil,
		value,
		valueBlind[:],
		valueBlind[:],
		nil,
		nil,
		nil)

	if err != nil {
		return
	}

	var fixedInputAssetTags []secp256k1.FixedAssetTag

	var fixedOutputAssetTag *secp256k1.FixedAssetTag

	fixedOutputAssetTag, err = secp256k1.FixedAssetTagParse(output.Asset.Id[:])

	for _, input := range inputs {
		var fixedAssetTag *secp256k1.FixedAssetTag
		fixedAssetTag, err = secp256k1.FixedAssetTagParse(input.Asset.Id[:])
		if err != nil {
			return
		}
		fixedInputAssetTags = append(fixedInputAssetTags, *fixedAssetTag)
	}

	seed32 := secp256k1.Random256()
	_, _, _, err = secp256k1.SurjectionproofAllocateInitialized(context, fixedInputAssetTags, len(fixedInputAssetTags), fixedOutputAssetTag, 10, seed32[:])
	output = privateOutput{
		publicOutput: publicOutput{
			Input: Input{
				Features: core.PlainOutput,
				Commit:   changeCommitment,
			},
			Proof:           hex.EncodeToString(proof),
			SurjectionProof: "",
		},
		ValueBlind: valueBlind,
		AssetBlind: assetBlind,
		Value:      value,
		Status:     0,
		Asset:      asset,
	}
	return
}
