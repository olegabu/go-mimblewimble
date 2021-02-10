package transfer

import (
	"encoding/hex"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-mimblewimble/wallet/utils"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func inputsAndOutputs(
	sg SecretGenerator,
	context *secp256k1.Context,
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
		secret, e := sg.Secret(context, walletInput.Index)
		if e != nil {
			err = errors.Wrapf(e, "cannot get secret for walletInput with key index %d", walletInput.Index)
			return
		}

		blind := secret[:]

		assetSecret, e := sg.Secret(context, walletInput.AssetIndex)
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
		changeOutput, changeBlind, e := utils.NewOutput(sg, context, change, ledger.PlainOutput, asset, OutputUnconfirmed)
		if e != nil {
			err = errors.Wrap(e, "cannot create change output")
			return
		}
		outputBlinds = append(outputBlinds, changeBlind)
		walletOutputs = append(walletOutputs, *changeOutput)
	}

	if receiveAmount > 0 {
		receiveOutput, receiveBlind, e := utils.NewOutput(sg, context, receiveAmount, ledger.PlainOutput, receiveAsset, OutputUnconfirmed)
		if e != nil {
			err = errors.Wrap(e, "cannot create receive output")
			return
		}
		outputBlinds = append(outputBlinds, receiveBlind)
		walletOutputs = append(walletOutputs, *receiveOutput)
	}

	// sum up slateInputs(-) and walletOutputs(+) blinding factors
	blindExcess, err = secp256k1.BlindSum(context, outputBlinds, inputBlinds)
	if err != nil {
		err = errors.Wrap(err, "cannot create blinding excess sum")
		return
	}

	return
}

func pubKeyFromSecretKey(context *secp256k1.Context, sk32 []byte) (*secp256k1.PublicKey, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(context, sk32)
	if res != 1 || pk == nil || err != nil {
		return nil, errors.Wrap(err, "cannot create pubKeyFromSecretKey")
	}

	return pk, nil
}

func sumPubKeys(context *secp256k1.Context, pubkeys []*secp256k1.PublicKey) (sum *secp256k1.PublicKey, err error) {
	res, sum, err := secp256k1.EcPubkeyCombine(context, pubkeys)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot sum public keys")
	}

	return
}
