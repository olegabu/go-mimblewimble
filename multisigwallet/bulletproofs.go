package multisigwallet

import (
	"encoding/hex"

	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) generatePublicTaus(blind []byte) (bulletproofsShare *BulletproofsShare, err error) {
	fakeBlind := [32]byte{1}
	fakeCommonNonce := make([]byte, 32)
	fakeCommit, err := secp256k1.Commit(t.context, fakeBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot create fakeCommit")
		return
	}

	_, _, publicTau1, publicTau2, err := secp256k1.BulletproofRangeproofProveMulti(t.context, nil, nil, nil, nil, nil,
		[]uint64{0}, [][]byte{fakeBlind[:]}, []*secp256k1.Commitment{fakeCommit}, &secp256k1.GeneratorH, 64, fakeCommonNonce, blind, nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot process first step of bulletproofs mpc protocol")
		return
	}

	return &BulletproofsShare{PublicTau1: publicTau1.Hex(t.context), PublicTau2: publicTau2.Hex(t.context)}, nil
}

func (t *Wallet) computeTaux(blind []byte, assetBlind []byte, slate *Slate) (taux []byte, err error) {
	commit, assetCommit, _, _, err := t.computeMultipartyCommit(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot computeMultipartyCommit")
		return
	}

	sumPublicTau1, sumPublicTau2, _, commonNonce, err := t.aggregatePartiesValues(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregatePartiesValues")
		return
	}

	_, taux, _, _, err = secp256k1.BulletproofRangeproofProveMulti(t.context, nil, nil, nil, sumPublicTau1, sumPublicTau2,
		[]uint64{uint64(slate.Amount)}, [][]byte{blind[:]}, []*secp256k1.Commitment{commit}, assetCommit, 64, commonNonce, blind, nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot process second step of bulletproofs mpc protocol")
		return
	}
	return
}

func (t *Wallet) aggregateProof(slate *Slate, commit *secp256k1.Commitment, assetCommit *secp256k1.Generator) (proof []byte, err error) {
	sumPublicTau1, sumPublicTau2, sumTaux, commonNonce, err := t.aggregatePartiesValues(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregatePartiesValues")
		return
	}

	fakeBlind := [32]byte{1}

	proof, _, _, _, err = secp256k1.BulletproofRangeproofProveMulti(t.context, nil, nil, sumTaux[:], sumPublicTau1, sumPublicTau2,
		[]uint64{uint64(slate.Amount)}, [][]byte{fakeBlind[:]}, []*secp256k1.Commitment{commit}, assetCommit, 64, commonNonce, fakeBlind[:], nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot process third step of bulletproofs mpc protocol")
		return
	}
	return
}

func (t *Wallet) aggregatePartiesValues(slate *Slate) (
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
