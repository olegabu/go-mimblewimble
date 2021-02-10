package transfer

import (
	"encoding/hex"
	"encoding/json"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/multisigwallet/types"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func Respond(
	sg SecretGenerator,
	context *secp256k1.Context,
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []SavedOutput,
	receiveAmount uint64,
	receiveAsset string,
	inSlate *Slate,
) (
	outSlateBytes []byte,
	walletOutputs []SavedOutput,
	walletSlate *SavedSlate,
	err error,
) {
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

	inSlate.Transaction.Body.Inputs = append(inSlate.Transaction.Body.Inputs, slateInputs...)

	// add responder output (receiver's in Send, payer's change in Invoice)
	for _, o := range walletOutputs {
		inSlate.Transaction.Body.Outputs = append(inSlate.Transaction.Body.Outputs, o.SlateOutput)
	}

	receiverPublicBlind, err := pubKeyFromSecretKey(context, blindExcess[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlind")
		return
	}

	// choose receiver nonce and calculate its public key
	receiverNonce, err := sg.Nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}
	receiverPublicNonce, err := pubKeyFromSecretKey(context, receiverNonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
	}

	// parse out sender public blind and public nonce
	senderPublicBlind := context.PublicKeyFromHex(inSlate.ParticipantData["0"].PublicBlindExcess)
	if senderPublicBlind == nil {
		err = errors.Wrap(err, "cannot get senderPublicBlindExcess")
		return
	}
	senderPublicNonce := context.PublicKeyFromHex(inSlate.ParticipantData["0"].PublicNonce)
	if senderPublicNonce == nil {
		err = errors.Wrap(err, "cannot get senderPublicNonce")
		return
	}

	// Combine sender and receiver public blinds and nonces
	sumPublicBlinds, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicBlindsBytes")
		return
	}
	sumPublicNonces, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicNoncesBytes")
		return
	}

	// Calculate message digest for the kernel signature
	msg := ledger.KernelSignatureMessage(inSlate.Transaction.Body.Kernels[0])

	// Create Receiver's partial signature
	receiverPartSig, err := secp256k1.AggsigSignPartial(
		context,
		blindExcess[:], receiverNonce[:],
		sumPublicNonces, sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate receiver's partial signature")
		return
	}

	// Update slate with the receiver's info
	receiverPartSigBytes := secp256k1.AggsigSignaturePartialSerialize(&receiverPartSig)
	receiverPartSigString := hex.EncodeToString(receiverPartSigBytes[:])
	inSlate.ParticipantData["1"] = &ParticipantData{
		PublicBlindExcess: receiverPublicBlind.Hex(context),
		PublicNonce:       receiverPublicNonce.Hex(context),
		PartSig:           &receiverPartSigString,
		Message:           nil,
		MessageSig:        nil,
	}

	outSlateBytes, err = json.Marshal(inSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	walletSlate = &SavedSlate{
		Slate: *inSlate,
		Nonce: receiverNonce,
	}

	return
}
