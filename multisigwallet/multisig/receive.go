package multisig

import (
	"encoding/hex"

	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/multisigwallet/types"
)

func Receive(wallet Wallet, amount uint64, asset string, combinedSlate *Slate, participantID string) (slate *Slate, walletOutput *SavedOutput, err error) {
	slate = combinedSlate
	if amount != uint64(slate.Amount) {
		err = errors.New("amount does not match slate's amount")
		return
	}

	walletOutput, blindValueAssetBlind, err := newOutput(wallet, amount, ledger.PlainOutput, asset, OutputUnconfirmed)
	if err != nil {
		return
	}

	kernelOffset, err := wallet.Nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for kernelOffset")
		return
	}

	blindExcess, err := secp256k1.BlindSum(wallet.GetContext(), [][]byte{blindValueAssetBlind[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}

	nonce, err := wallet.Nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	commits, err := commitsFromBlinds(wallet.GetContext(), blindExcess[:], nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot get commits from blinds")
		return
	}

	publicBlindExcess := commits[0]
	publicNonce := commits[1]

	slate.ParticipantData[participantID] = &ParticipantData{
		PublicBlindExcess: publicBlindExcess.String(),
		PublicNonce:       publicNonce.String(),
	}

	aggregatedPublicKey, aggregatedPublicNonce, err := getAggregatedPublicKeyAndNonce(wallet.GetContext(), slate)
	if err != nil {
		err = errors.Wrap(err, "cannot getAggregatedPublicKeyAndNonce")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	var privateKey [32]byte
	privateKey, err = secp256k1.BlindSum(wallet.GetContext(), [][]byte{blindExcess[:]}, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot compute private key")
		return
	}

	partialSignature, err := secp256k1.AggsigSignPartial(wallet.GetContext(), privateKey[:], nonce[:], aggregatedPublicNonce, aggregatedPublicKey, msg)
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
		return nil, nil, err
	}

	totalOffset, err := secp256k1.BlindSum(wallet.GetContext(), [][]byte{offset[:], kernelOffset[:]}, nil)
	if err != nil {
		return nil, nil, err
	}

	slate.Transaction.Offset = hex.EncodeToString(totalOffset[:])

	return
}
