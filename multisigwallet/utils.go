package multisigwallet

import (
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func commitFromBlind(context *secp256k1.Context, blind []byte) (commit *secp256k1.Commitment, err error) {
	return secp256k1.Commit(context, blind, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
}

func commitsFromBlinds(context *secp256k1.Context, blinds ...[]byte) (commits []*secp256k1.Commitment, err error) {
	for _, blind := range blinds {
		commit, e := commitFromBlind(context, blind)
		if e != nil {
			err = errors.Wrap(e, "cannot create commit from blind")
			return
		}
		commits = append(commits, commit)
	}
	return
}

// blind + v * assetBlind
func (t *Wallet) getBlindValueAssetBlind(output SavedOutput) (blindValueAssetBlind [32]byte, err error) {
	outputBlind, err := t.secret(output.Index)
	if err != nil {
		err = errors.Wrap(err, "cannot get input blind")
		return
	}

	outputAssetBlind, err := t.secret(output.AssetIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot get input asset blind")
		return
	}

	blindValueAssetBlind, err = secp256k1.BlindValueGeneratorBlindSum(output.Value, outputAssetBlind[:], outputBlind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}
	return
}

func (t *Wallet) pubKeyFromSecretKey(sk32 []byte) (*secp256k1.PublicKey, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(t.context, sk32)
	if res != 1 || pk == nil || err != nil {
		return nil, errors.Wrap(err, "cannot create pubKeyFromSecretKey")
	}

	return pk, nil
}

func findCorrespondingParticipantData(slates []*Slate, publicBlind string) (slate *ParticipantData, err error) {
	for _, slate := range slates {
		for _, participantData := range slate.ParticipantData {
			if participantData.PublicBlind == publicBlind && participantData.PartSig != nil {
				return &participantData, nil
			}
		}
	}
	return nil, errors.New("cannot find partial signature")
}
