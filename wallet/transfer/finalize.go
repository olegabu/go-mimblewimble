package transfer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-mimblewimble/wallet/utils"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func Finalize(
	responseSlate *Slate,
	senderSlate *SavedSlate,
) (
	ledgerTxBytes []byte,
	walletTx SavedTransaction,
	err error,
) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot ContextCreate")
		return
	}
	defer secp256k1.ContextDestroy(context)

	// get secret keys from sender's responseSlate that has blind and secret nonces
	senderBlind := senderSlate.Blind[:]
	senderNonce := senderSlate.Nonce[:]
	// calculate public keys from secret keys
	senderPublicBlind, _ := pubKeyFromSecretKey(context, senderBlind)
	senderPublicNonce, _ := pubKeyFromSecretKey(context, senderNonce)

	// parse out public blinds and nonces for both sender and receiver from the responseSlate
	if len(responseSlate.ParticipantData) != 2 {
		err = errors.New("expected 2 entries in ParticipantData")
		return
	}

	if senderSlate.Amount != responseSlate.Amount || senderSlate.Asset != responseSlate.Asset || senderSlate.ReceiveAmount != responseSlate.ReceiveAmount || senderSlate.ReceiveAsset != responseSlate.ReceiveAsset {
		err = errors.Errorf("amounts and assets in the response slate do not match; sent(%d %s %d %s) received(%d %s %d %s)",
			senderSlate.Amount, senderSlate.Asset, senderSlate.ReceiveAmount, senderSlate.ReceiveAsset,
			responseSlate.Amount, responseSlate.Asset, responseSlate.ReceiveAmount, responseSlate.ReceiveAsset)
		return

	}

	// get public keys from responseSlate
	senderPublicBlindFromResponseSlate := context.PublicKeyFromHex(responseSlate.ParticipantData["0"].PublicBlindExcess)
	senderPublicNonceFromResponseSlate := context.PublicKeyFromHex(responseSlate.ParticipantData["0"].PublicNonce)

	// verify the response we've got from Receiver has Sender's public key and secret unchanged
	if (0 != bytes.Compare(senderPublicBlind.Bytes(context), senderPublicBlindFromResponseSlate.Bytes(context))) ||
		(0 != bytes.Compare(senderPublicNonce.Bytes(context), senderPublicNonceFromResponseSlate.Bytes(context))) {
		err = errors.Wrap(err, "public keys mismatch, calculated values are not the same as loaded from responseSlate")
		return
	}

	receiverPublicBlind := context.PublicKeyFromHex(responseSlate.ParticipantData["1"].PublicBlindExcess)
	receiverPublicNonce := context.PublicKeyFromHex(responseSlate.ParticipantData["1"].PublicNonce)

	// combine sender and receiver public blinds and nonces
	sumPublicBlinds, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicBlinds")
		return
	}
	sumPublicNonces, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicNonces")
		return
	}

	// calculate message hash
	msg := ledger.KernelSignatureMessage(responseSlate.Transaction.Body.Kernels[0])

	// decode receiver's partial signature
	receiverPartSigBytes, err := hex.DecodeString(*responseSlate.ParticipantData["1"].PartSig)
	if err != nil {
		err = errors.Wrap(err, "cannot decode receiverPartSigBytes from hex")
		return
	}
	receiverPartSig, err := secp256k1.AggsigSignaturePartialParse(receiverPartSigBytes)
	if err != nil {
		err = errors.Wrap(err, "cannot parse receiverPartialSig from bytes")
		return
	}

	// verify receiver's partial signature
	err = secp256k1.AggsigVerifyPartial(
		context,
		&receiverPartSig,
		sumPublicNonces,
		receiverPublicBlind,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify receiver partial signature")
		return
	}

	// calculate sender's partial signature
	senderPartSig, err := secp256k1.AggsigSignPartial(
		context,
		senderBlind,
		senderNonce,
		sumPublicNonces,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate sender partial signature")
		return
	}

	// verify sender's partial signature
	err = secp256k1.AggsigVerifyPartial(
		context,
		&senderPartSig,
		sumPublicNonces,
		senderPublicBlind,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify sender partial signature")
		return
	}

	// add sender and receiver partial signatures
	finalSig, err := secp256k1.AggsigAddSignaturesSingle(
		context,
		[]*secp256k1.AggsigSignaturePartial{
			&senderPartSig,
			&receiverPartSig,
		},
		sumPublicNonces)
	if err != nil {
		err = errors.Wrap(err, "cannot add sender and receiver partial signatures")
		return
	}

	// verify final signature
	err = secp256k1.AggsigVerifySingle(
		context,
		&finalSig,
		msg,
		nil,
		sumPublicBlinds,
		sumPublicBlinds,
		nil,
		false,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify excess signature")
		return
	}

	slateTx := responseSlate.Transaction

	var inputCommitments, outputCommitments []*secp256k1.Commitment

	// collect input commitments
	for _, input := range slateTx.Body.Inputs {
		com, e := secp256k1.CommitmentFromString(input.Commit)
		if e != nil {
			err = errors.Wrap(e, "error parsing input commitment")
			return
		}
		inputCommitments = append(inputCommitments, com)
	}

	// collect output commitments
	for _, output := range slateTx.Body.Outputs {
		com, e := secp256k1.CommitmentFromString(output.Commit)
		if e != nil {
			err = errors.Wrap(e, "error parsing output commitment")
			return
		}
		outputCommitments = append(outputCommitments, com)
	}

	offsetBytes, err := hex.DecodeString(slateTx.Offset)
	if err != nil {
		err = errors.Wrap(err, "cannot get offsetBytes")
		return
	}

	kernelExcess, err := ledger.CalculateExcess(
		context,
		inputCommitments,
		outputCommitments,
		offsetBytes,
		uint64(slateTx.Body.Kernels[0].Fee))
	if err != nil {
		err = errors.Wrap(err, "cannot calculate kernel excess")
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(context, kernelExcess)
	if err != nil {
		err = errors.Wrap(err, "excessPublicKey: CommitmentToPublicKey failed")
		return
	}

	// verify final sig with pk from excess
	err = secp256k1.AggsigVerifySingle(
		context,
		&finalSig,
		msg,
		sumPublicNonces,
		excessPublicKey,
		excessPublicKey,
		nil,
		false)
	if err != nil {
		err = errors.Wrap(err, "AggsigVerifySingle failed to verify the finalSig with excessPublicKey")
		return
	}

	excessSig := secp256k1.AggsigSignatureSerialize(context, &finalSig)

	ledgerTx := ledger.Transaction{
		Offset: slateTx.Offset,
		ID:     slateTx.ID,
		Body: ledger.TransactionBody{
			Kernels: []ledger.TxKernel{
				{
					Excess:    kernelExcess.String(),
					ExcessSig: hex.EncodeToString(excessSig[:]),
				},
			},
		},
	}

	for _, o := range slateTx.Body.Inputs {
		ledgerTx.Body.Inputs = append(ledgerTx.Body.Inputs, o.Input)
	}

	for _, o := range slateTx.Body.Outputs {
		e := utils.AddSurjectionProof(context, &o, slateTx.Body.Inputs, senderSlate.Asset)
		if e != nil {
			err = errors.Wrap(e, "cannot addSurjectionProof")
			return
		}
		ledgerTx.Body.Outputs = append(ledgerTx.Body.Outputs, o.Output)
	}

	ledgerTxBytes, err = json.Marshal(ledgerTx)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal ledgerTx to json")
		return
	}

	walletTx = SavedTransaction{
		Transaction: ledgerTx,
		Status:      TransactionUnconfirmed,
	}

	return
}
