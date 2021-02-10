package transfer

import (
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func Initiate(
	sg SecretGenerator,
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
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot ContextCreate")
		return
	}
	defer secp256k1.ContextDestroy(context)

	slateInputs, walletOutputs, blindExcess, err := inputsAndOutputs(
		sg,
		context,
		amount,
		fee,
		asset,
		change,
		walletInputs,
		receiveAmount,
		receiveAsset)
	if err != nil {
		err = errors.Wrap(err, "cannot create slateInputs and walletOutputs")
		return
	}

	// generate secret nonce
	nonce, err := sg.Nonce(context)
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	// generate random kernel offset
	kernelOffset, err := sg.Nonce(context)
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for kernelOffset")
		return
	}

	// subtract kernel offset from blinding excess
	sumBlinds, err := secp256k1.BlindSum(context, [][]byte{blindExcess[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}

	publicBlindExcess, err := pubKeyFromSecretKey(context, sumBlinds[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlindExcess")
		return
	}

	publicNonce, err := pubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
	}

	var slateOutputs []SlateOutput
	for _, o := range walletOutputs {
		slateOutputs = append(slateOutputs, o.SlateOutput)
	}

	slate := &Slate{
		VersionInfo: VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 2,
		Transaction: SlateTransaction{
			ID:     uuid.New(),
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
		ParticipantData: map[string]*ParticipantData{"0": {
			PublicBlindExcess: publicBlindExcess.Hex(context),
			PublicNonce:       publicNonce.Hex(context),
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
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}
