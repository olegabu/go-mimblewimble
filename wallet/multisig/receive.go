package multisig

import (
	"encoding/hex"

	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-mimblewimble/wallet/utils"
)

func Receive(
	sg SecretGenerator,
	amount uint64,
	asset string,
	combinedSlate *Slate,
	participantID string,
) (
	slate *Slate,
	walletOutput *SavedOutput,
	err error,
) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot create secp256k1 context")
		return
	}
	defer secp256k1.ContextDestroy(context)

	slate = combinedSlate
	if amount != uint64(slate.Amount) {
		err = errors.New("amount does not match slate's amount")
		return
	}

	walletOutput, blindValueAssetBlind, err := utils.NewOutput(sg, context, amount, ledger.PlainOutput, asset, OutputUnconfirmed)
	if err != nil {
		err = errors.Wrap(err, "cannot create new output")
		return
	}

	partialOffset, err := sg.Nonce(context)
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for partial offset")
		return
	}

	blindExcess, err := secp256k1.BlindSum(context, [][]byte{blindValueAssetBlind[:]}, [][]byte{partialOffset[:]})
	if err != nil {
		err = errors.Wrap(err, "cannot compute excess: blind + value * assetBlind - partialOffset")
		return
	}

	nonce, err := sg.Nonce(context)
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	commits, err := commitsFromBlinds(context, blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot compute public blind and public nonce")
		return
	}
	publicBlindExcess := commits[0]
	publicNonce := commits[1]

	slate.ParticipantData[participantID] = &ParticipantData{
		PublicBlindExcess: publicBlindExcess.String(),
		PublicNonce:       publicNonce.String(),
	}

	aggregatedPublicKey, aggregatedPublicNonce, err := getAggregatedPublicKeyAndNonce(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot compute aggregated public key and aggregated public nonce")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])
	partialSignature, err := secp256k1.AggsigSignPartial(context, blindExcess[:], nonce[:], aggregatedPublicNonce, aggregatedPublicKey, msg)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate receiver's partial signature")
		return
	}
	partialSignatureBytes := secp256k1.AggsigSignaturePartialSerialize(&partialSignature)
	partialSignatureString := hex.EncodeToString(partialSignatureBytes[:])

	slate.ParticipantData[participantID].PartSig = &partialSignatureString
	slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, walletOutput.SlateOutput)
	slate.NumParticipants++

	offset, err := hex.DecodeString(slate.Transaction.Offset)
	if err != nil {
		err = errors.Wrap(err, "cannot parse transaction's offset")
		return
	}

	totalOffset, err := secp256k1.BlindSum(context, [][]byte{offset[:], partialOffset[:]}, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot add partial offset to transaction's offset")
		return
	}
	slate.Transaction.Offset = hex.EncodeToString(totalOffset[:])
	return
}
