package multisig

import (
	"encoding/hex"

	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func commitsFromBlinds(context *secp256k1.Context, blinds ...[]byte) (commits []*secp256k1.Commitment, err error) {
	for _, blind := range blinds {
		commit, e := secp256k1.Commit(context, blind, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
		if e != nil {
			err = errors.Wrap(e, "cannot compute blind * G")
			return
		}
		commits = append(commits, commit)
	}
	return
}

func computeBlindValueAssetBlind(sg SecretGenerator, context *secp256k1.Context, output SavedOutput) (blindValueAssetBlind [32]byte, err error) {
	var blind [32]byte
	if output.PartialBlind != nil {
		blind = *output.PartialBlind
	} else {
		blind, err = sg.Secret(context, output.Index)
		if err != nil {
			err = errors.Wrap(err, "cannot get blind by index")
			return
		}
	}

	var assetBlind [32]byte
	if output.PartialBlind != nil {
		assetBlind = *output.PartialAssetBlind
	} else {
		assetBlind, err = sg.Secret(context, output.AssetIndex)
		if err != nil {
			err = errors.Wrap(err, "cannot get asset blind by index")
			return
		}
	}

	blindValueAssetBlind, err = secp256k1.BlindValueGeneratorBlindSum(output.Value, assetBlind[:], blind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot compute blind + value * assetBlind")
		return
	}
	return
}

func aggregateBulletproofMPCValues(context *secp256k1.Context, slate *Slate) (
	sumPublicTau1 *secp256k1.PublicKey,
	sumPublicTau2 *secp256k1.PublicKey,
	sumTaux [32]byte,
	commonNonce []byte,
	err error,
) {
	publicTau1s, publicTau2s, tauxs := []*secp256k1.PublicKey{}, []*secp256k1.PublicKey{}, [][]byte{}
	commonNonce = make([]byte, 32)
	for partyID, participantData := range slate.ParticipantData {
		if !participantData.IsMultisigFundOwner {
			continue
		}

		// TODO: Check it
		publicNonceBytes, e := hex.DecodeString(participantData.PublicNonce)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse public nonce of participant with id %s", partyID)
			return
		}
		for i := 0; i < 32; i++ {
			commonNonce[i] = commonNonce[i] ^ publicNonceBytes[i+1]
		}

		publicTau1Bytes, e := hex.DecodeString(participantData.BulletproofShare.PublicTau1)
		if e != nil {
			err = errors.Wrap(e, "cannot decode publicTau1")
			return
		}

		_, publicTau1, e := secp256k1.EcPubkeyParse(context, publicTau1Bytes)
		if e != nil {
			err = errors.Wrap(e, "cannot parse publicTau1")
			return
		}
		publicTau1s = append(publicTau1s, publicTau1)

		publicTau2Bytes, e := hex.DecodeString(participantData.BulletproofShare.PublicTau2)
		if e != nil {
			err = errors.Wrap(e, "cannot decode publicTau2")
			return
		}

		_, publicTau2, e := secp256k1.EcPubkeyParse(context, publicTau2Bytes)
		if e != nil {
			err = errors.Wrap(e, "cannot parse publicTau2")
			return
		}
		publicTau2s = append(publicTau2s, publicTau2)

		if participantData.BulletproofShare.Taux != "" {
			taux, e := hex.DecodeString(participantData.BulletproofShare.Taux)
			if e != nil {
				err = errors.Wrap(e, "cannot decode taux")
				return
			}
			tauxs = append(tauxs, taux)
		}
	}

	_, sumPublicTau1, err = secp256k1.EcPubkeyCombine(context, publicTau1s)
	if err != nil {
		err = errors.Wrap(err, "cannot combine publicTau1s")
		return
	}

	_, sumPublicTau2, err = secp256k1.EcPubkeyCombine(context, publicTau2s)
	if err != nil {
		err = errors.Wrap(err, "cannot combine publicTau2s")
		return
	}

	if len(tauxs) > 0 {
		sumTaux, err = secp256k1.BlindSum(context, tauxs, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot combine tauxs")
			return
		}
	}
	return
}
