package multiasset

import (
	"encoding/hex"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func calculateOutputValues(
	fee AssetBalance,
	walletInputs []PrivateOutput, // the assets Alice owns hence pays with
	spends []AssetBalance) ( //the assets Alice pays with
	spentInputs []Input,
	inputBlinds [][]byte,
	changeValues map[Asset]uint64, //helper map for change outputs
	err error,
) {
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

	changeValues = make(map[Asset]uint64)
	//loop through inputs about to be spent
	//we couldn't do it while looping through spends, because there could be duplicate assets both among owned assets and spends
	for id, input := range spentInputMap {
		if inputsById[id].Value > input.Value {
			changeValues[input.Asset] = inputsById[id].Value - input.Value
		}
		spentInputs = append(spentInputs, (*input).PublicOutput.Input)
		inputBlinds = append(inputBlinds, input.ValueBlind[:])
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
	slateOutput = SlateOutput{
		PublicOutput: publicOutput,
		AssetBlind:   hex.EncodeToString(assetBlind[:]),
		Asset:        asset,
	}
	privateOutput = PrivateOutput{
		SlateOutput: slateOutput,
		ValueBlind:  valueBlind,
		Value:       value,
		Status:      0,
	}

	return
}
