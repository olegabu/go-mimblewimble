package multiasset

import (
	"encoding/hex"
	"github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

type Wallet struct {
	inputs  []PrivateOutput
	context *secp256k1.Context
}

func (w Wallet) calculateOutputValues(
	fee AssetBalance,
	expenses []AssetBalance) ( //the assets Alice spends
	spentInputs []PrivateOutput,
	//inputBlinds [][]byte,
	changeValues map[Asset]uint64, //helper map for change outputs
	err error,
) {
	inputs := w.inputs
	// Group all expenses by asset id to make the tallying easier
	totalExpenseByAsset := make(map[Asset]uint64)
	//initialize output helper map
	for _, expense := range expenses {
		totalExpenseByAsset[expense.Asset] += expense.Value
	}
	if totalExpenseByAsset[fee.Asset] > 0 {
		totalExpenseByAsset[fee.Asset] += fee.Value
	}

	// Group all owned inputs by asset id to make the tallying easier

	//initialize inputs helper maps
	myBalance := make(map[Asset]uint64)
	for _, input := range inputs {
		myBalance[input.Asset] += input.Value
	}

	//check for any overspending
	for asset, value := range totalExpenseByAsset {
		if myBalance[asset] < value {
			err = errors.New("insufficient funds")
			return
		}
	}

	changeValues = make(map[Asset]uint64)

	for asset, value := range totalExpenseByAsset {
		remainder := value
		for _, input := range inputs {
			spentInputs = append(spentInputs, input)
			if input.Value >= remainder {
				changeValues[asset] = input.Value - remainder
				remainder = 0
				break
			} else {
				remainder = remainder - input.Value
			}
		}
	}

	return
}

func (w *Wallet) createOutput(balance AssetBalance) (privateOutput PrivateOutput, err error) {
	context := w.context
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
	asset, value := balance.Asset, balance.Value

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

	publicOutput := PublicOutput{
		Input: Input{
			Features: core.PlainOutput,
			Commit:   outputCommitment,
		},
		Proof:           hex.EncodeToString(proof),
		SurjectionProof: "",
	}

	privateOutput = PrivateOutput{
		SlateOutput: SlateOutput{
			PublicOutput: publicOutput,
			AssetBlind:   hex.EncodeToString(assetBlind[:]),
			Asset:        asset,
		},
		ValueBlind: valueBlind,
		Value:      value,
		Status:     0,
	}

	return
}
