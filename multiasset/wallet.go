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
	walletInputs []PrivateOutput, // the assets Alice owns hence pays with
	purchases []AssetBalance, // the assets Alice buys
	spends []AssetBalance) ( //the assets Alice pays with
	slateBytes []byte,
	outputs []PrivateOutput,
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
	inputsByAsset := make(map[string][]PrivateOutput)

	inputsById := make(map[string]PrivateOutput)

	offerBalance[fee.asset.Name] += fee.amount

	//initialize output helper map
	for _, spend := range spends {
		offerBalance[spend.asset.Name] += spend.amount
	}

	//initialize inputs helper maps
	myBalance := make(map[string]uint64)
	for _, input := range walletInputs {
		myBalance[input.Asset.Name] += input.Value
		inputsByAsset[input.Asset.Name] = append(inputsByAsset[input.Asset.Name], input)
		inputsById[input.Commit.ValueCommitment] = input
	}

	//check for any overspending
	for assetId, value := range offerBalance {
		if myBalance[assetId] < value {
			err = errors.New("insufficient funds")
			return
		}
	}

	spentInputMap := make(map[string]*PrivateOutput)

	//for every asset output Alice wishes to create by spending her funds
	for _, spend := range spends {
		//get the value of output
		remainder := spend.amount
		//loop through inputs and mark those that are about to used in this transaction
		//
		for _, input := range inputsByAsset[spend.asset.Name] {

			//this input is already spent, proceed to the next one
			if input.Value == 0 {
				continue
			}
			//since this input was not spent before, remember it
			spentInputMap[input.Commit.ValueCommitment] = &input

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
	var spentInputs []Input
	//helper map for change outputs
	changeAmountsToBeCreated := make(map[Asset]uint64)

	//loop through inputs about to be spent
	//we couldn't do it while looping through spends, because there could be duplicate assets both among owned assets and spends
	for id, input := range spentInputMap {
		if inputsById[id].Value > input.Value {
			changeAmountsToBeCreated[input.Asset] = inputsById[id].Value - input.Value
		}
		spentInputs = append(spentInputs, (*input).PublicOutput.Input)
	}

	var privateOutput PrivateOutput
	var slateOutput SlateOutput

	var outputBlinds, inputBlinds [][]byte

	for _, input := range walletInputs {
		inputBlinds = append(inputBlinds, input.ValueBlind[:])
	}

	//create change outputs with token commitment and surjection proof
	var slateOutputs []SlateOutput
	for asset, changeValue := range changeAmountsToBeCreated {

		privateOutput, slateOutput, err = createOutput(context, AssetBalance{
			asset:  asset,
			amount: changeValue,
		})

		if err != nil {
			return
		}
		slateOutputs = append(slateOutputs, slateOutput)
		outputs = append(outputs, privateOutput)
		outputBlinds = append(outputBlinds, privateOutput.ValueBlind[:])
	}

	//create purchase outputs with token commitment. We can't create
	for _, purchase := range purchases {
		privateOutput, slateOutput, err = createOutput(context, purchase)
		if err != nil {
			return
		}
		outputs = append(outputs, privateOutput)
	}

	var nonce, kernelOffset [32]byte
	var publicBlindExcess, publicNonce *secp256k1.PublicKey

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
	//copy(senderSlate.SenderNonce[:], nonce[:])
	//copy(senderSlate.SumSenderBlinds[:], blindExcess[:])
	//senderSlate.Status = SlateSent
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
				Transaction: Transaction{
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
		SumSenderBlinds: blindExcess,
		SenderNonce:     nonce,
	}
	return
}

func createOutput(context *secp256k1.Context, balance AssetBalance) (privateOutput PrivateOutput, slateOutput SlateOutput, err error) {
	var assetCommitment *secp256k1.Generator
	var serializedAssetCommitment [33]byte
	var valueBlind, assetBlind [32]byte
	valueBlind, err = wallet.Secret(context)
	if err != nil {
		return
	}
	assetBlind, err = wallet.Secret(context)
	if err != nil {
		return
	}
	asset, value := balance.asset, balance.amount

	assetCommitment, err = secp256k1.GeneratorGenerateBlinded(context, asset.seed(), assetBlind[:])
	if err != nil {
		return
	}
	serializedAssetCommitment = secp256k1.GeneratorSerialize(context, assetCommitment)

	valueCommitment, _ := secp256k1.Commit(context, valueBlind[:], value, assetCommitment, &secp256k1.GeneratorG)
	outputCommitment := Commitment{
		ValueCommitment: valueCommitment.Hex(context),
		AssetCommitment: hex.EncodeToString(serializedAssetCommitment[:]),
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
	publicOutput := PublicOutput{
		Input: Input{
			Features: core.PlainOutput,
			Commit:   outputCommitment,
		},
		Proof:           hex.EncodeToString(proof),
		SurjectionProof: surjectionProof,
	}

	privateOutput = PrivateOutput{
		PublicOutput: publicOutput,
		ValueBlind:   valueBlind,
		AssetBlind:   assetBlind,
		Value:        value,
		Status:       0,
		Asset:        asset,
	}
	slateOutput = SlateOutput{
		PublicOutput: publicOutput,
		AssetBlind:   hex.EncodeToString(assetBlind[:]),
		Asset:        asset,
	}
	return
}
