package multisigwallet

import (
	"encoding/hex"

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
	blindValueAssetBlind, err = secp256k1.BlindValueGeneratorBlindSum(output.Value, output.PartialAssetBlind[:], output.Blind[:])
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

func (t *Wallet) aggregateBulletproofMPCValues(slate *Slate) (
	sumPublicTau1 *secp256k1.PublicKey,
	sumPublicTau2 *secp256k1.PublicKey,
	sumTaux [32]byte,
	commonNonce []byte,
	err error,
) {
	publicTau1s := make([]*secp256k1.PublicKey, 0)
	publicTau2s := make([]*secp256k1.PublicKey, 0)
	tauxs := make([][]byte, 0)
	commonNonce = make([]byte, 32)
	for _, participantData := range slate.ParticipantData {
		// TODO: Check it
		publicNonceBytes, e := hex.DecodeString(participantData.PublicNonce)
		if e != nil {
			err = errors.Wrap(e, "cannot DecodeString")
			return
		}

		for i := 0; i < 32; i++ {
			commonNonce[i] = commonNonce[i] ^ publicNonceBytes[i+1]
		}

		publicTau1Bytes, e := hex.DecodeString(participantData.BulletproofsShare.PublicTau1)
		if e != nil {
			err = errors.Wrap(e, "cannot decode PublicTau1")
			return
		}

		_, publicTau1, e := secp256k1.EcPubkeyParse(t.context, publicTau1Bytes)
		if e != nil {
			err = errors.Wrap(e, "cannot parse PublicTau1")
			return
		}
		publicTau1s = append(publicTau1s, publicTau1)

		publicTau2Bytes, e := hex.DecodeString(participantData.BulletproofsShare.PublicTau2)
		if e != nil {
			err = errors.Wrap(e, "cannot decode PublicTau2")
			return
		}

		_, publicTau2, e := secp256k1.EcPubkeyParse(t.context, publicTau2Bytes)
		if e != nil {
			err = errors.Wrap(e, "cannot parse PublicTau2")
			return
		}
		publicTau2s = append(publicTau2s, publicTau2)

		if participantData.BulletproofsShare.Taux != "" {
			taux, e := hex.DecodeString(participantData.BulletproofsShare.Taux)
			if e != nil {
				err = errors.Wrap(e, "cannot decode Taux")
				return
			}
			tauxs = append(tauxs, taux)
		}
	}

	_, sumPublicTau1, err = secp256k1.EcPubkeyCombine(t.context, publicTau1s)
	if err != nil {
		err = errors.Wrap(err, "cannot combine PublicTau1s")
		return
	}

	_, sumPublicTau2, err = secp256k1.EcPubkeyCombine(t.context, publicTau2s)
	if err != nil {
		err = errors.Wrap(err, "cannot combine PublicTau2s")
		return
	}

	if len(tauxs) > 0 {
		sumTaux, err = secp256k1.BlindSum(t.context, tauxs, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot sum tauxs")
			return
		}
	}
	return
}
