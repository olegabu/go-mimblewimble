package multisigwallet

import (
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func commitsFromBlinds(context *secp256k1.Context, blinds ...[]byte) (commits []*secp256k1.Commitment, err error) {
	for _, blind := range blinds {
		commit, e := secp256k1.Commit(context, blind, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
		if e != nil {
			err = errors.Wrap(e, "cannot create commit from blind")
			return
		}
		commits = append(commits, commit)
	}
	return
}

// blind + v * assetBlind
func (t *Wallet) computeBlindValueAssetBlind(output SavedOutput) (blindValueAssetBlind [32]byte, err error) {
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

func findCorrespondingParticipantData(slates []*Slate, participantID string) (slate *ParticipantData, err error) {
	for _, slate := range slates {
		if slate.ParticipantData[participantID].PartSig != nil {
			return slate.ParticipantData[participantID], nil
		}
	}
	return nil, errors.New("cannot find partial signature")
}
