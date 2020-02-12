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
	walletInputs []privateOutput, // the assets Alice owns hence pays with
	purchases []AssetBalance, // the assets Alice buys
	spends []AssetBalance) ( //the assets Alice pays with
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

	// Group all spends by asset id to make the tallying easier
	offerBalance := make(map[string]uint64)

	// Group all owned inputs by asset id to make the tallying easier
	inputsByAsset := make(map[string][]privateOutput)

	inputsById := make(map[string]privateOutput)

	offerBalance[fee.asset.name] += fee.amount

	//initialize output helper map
	for _, spend := range spends {
		offerBalance[spend.asset.name] += spend.amount
	}

	//initialize inputs helper maps
	myBalance := make(map[string]uint64)
	for _, input := range walletInputs {
		myBalance[input.Asset.name] += input.Value
		inputsByAsset[input.Asset.name] = append(inputsByAsset[input.Asset.name], input)
		inputsById[input.Commit.ValueCommitment] = input
	}

	//check for any overspending
	for assetId, value := range offerBalance {
		if myBalance[assetId] < value {
			err = errors.New("insufficient funds")
			return
		}
	}

	inputsToBeSpent := make(map[string]*privateOutput)

	//for every asset output Alice wishes to create by spending her funds
	for _, spend := range spends {
		//get the value of output
		remainder := spend.amount
		//loop through inputs and mark those that are about to used in this transaction
		//
		for _, input := range inputsByAsset[spend.asset.name] {

			//this input is already spent, proceed to the next one
			if input.Value == 0 {
				continue
			}
			//since this input was not spent before, remember it
			inputsToBeSpent[input.Commit.ValueCommitment] = &input

			//if we have not less than we need, decrease the value and go to the next spend
			if input.Value-remainder >= 0 {
				input.Value = input.Value - remainder
				remainder = 0
				break
			}
			//since this specific input has insufficient funds, decrease the value and go to the next
			input.Value = 0
			remainder = remainder - input.Value

		}

	}
	//helper map for change outputs
	changeAmountsToBeCreated := make(map[Asset]uint64)

	//loop through inputs about to be spent
	//we couldn't do it while looping through spends, because there could be duplicate assets both among owned assets and spends
	for id, input := range inputsToBeSpent {
		if inputsById[id].Value > input.Value {
			changeAmountsToBeCreated[input.Asset] = inputsById[id].Value - input.Value
		}
	}

	var output privateOutput

	var outputBlinds, inputBlinds [][]byte

	for _, input := range walletInputs {
		inputBlinds = append(inputBlinds, input.ValueBlind[:])
	}

	//create change outputs with token commitment surjection proof
	for asset, changeValue := range changeAmountsToBeCreated {

		output, err = createOutputForPayment(context, AssetBalance{
			asset:  asset,
			amount: changeValue,
		}, walletInputs)

		if err != nil {
			return
		}
		outputs = append(outputs, output)
		outputBlinds = append(outputBlinds, output.ValueBlind[:])
	}

	//create purchase outputs without token commitments surjection proof
	for _, purchase := range purchases {
		output, err = createOutputForPurchase(context, purchase)
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
				Amount:          spends,
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
func createOutputForPayment(ctx *secp256k1.Context, balance AssetBalance, inputs []privateOutput) (output privateOutput, err error) {
	return createOutput(ctx, balance, inputs)
}

func createOutputForPurchase(ctx *secp256k1.Context, balance AssetBalance) (output privateOutput, err error) {
	return createOutput(ctx, balance, []privateOutput{})
}
func createOutput(context *secp256k1.Context, balance AssetBalance, inputs []privateOutput) (output privateOutput, err error) {
	valueBlind, _ := wallet.Secret(context)
	assetBlind, _ := wallet.Secret(context)

	asset, value := balance.asset, balance.amount
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

	surjectionProof := ""

	/*
		The surjection proof proves that for a particular output there is at least one corresponding input with the same asset id.
		The sender must create both change outputs and outputs which she wishes to acquire as a result of this transaction,
		because she must generate blinding factors for them to be available for later spending.
	*/
	if len(inputs) > 0 {
		var fixedInputAssetTags []secp256k1.FixedAssetTag
		var proof *secp256k1.Surjectionproof
		var inputIndex int
		var inputBlindingKeys [][]byte
		var outputBlindingKey []byte
		var fixedOutputAssetTag *secp256k1.FixedAssetTag
		var ephemeralInputTags []secp256k1.Generator
		var ephemeralOutputTag *secp256k1.Generator

		fixedOutputAssetTag, err = secp256k1.FixedAssetTagParse(asset.Id[:])

		for _, input := range inputs {
			var fixedAssetTag *secp256k1.FixedAssetTag
			var tokenCommitment *secp256k1.Generator
			fixedAssetTag, err = secp256k1.FixedAssetTagParse(input.Asset.Id[:])

			if err != nil {
				return
			}
			fixedInputAssetTags = append(fixedInputAssetTags, *fixedAssetTag)

			tokenCommitment, err = secp256k1.GeneratorParse(context, []byte(input.Commit.AssetCommitment))
			if err != nil {
				return
			}
			ephemeralInputTags = append(ephemeralInputTags, *tokenCommitment)

			inputBlindingKeys = append(inputBlindingKeys, input.AssetBlind[:])
		}

		ephemeralOutputTag, err = secp256k1.GeneratorParse(context, []byte(changeCommitment.AssetCommitment))

		if err != nil {
			return
		}

		seed32 := secp256k1.Random256()

		_, proof, inputIndex, err = secp256k1.SurjectionproofAllocateInitialized(context, fixedInputAssetTags, 1, fixedOutputAssetTag, 10, seed32[:])

		err = secp256k1.SurjectionproofGenerate(context, proof, ephemeralInputTags[:], *ephemeralOutputTag, inputIndex, inputBlindingKeys[inputIndex][:], outputBlindingKey[:])
		if err != nil {
			return
		}
	}

	output = privateOutput{
		publicOutput: publicOutput{
			Input: Input{
				Features: core.PlainOutput,
				Commit:   changeCommitment,
			},
			Proof:           hex.EncodeToString(proof),
			SurjectionProof: surjectionProof,
		},
		ValueBlind: valueBlind,
		AssetBlind: assetBlind,
		Value:      value,
		Status:     0,
		Asset:      asset,
	}
	return
}
