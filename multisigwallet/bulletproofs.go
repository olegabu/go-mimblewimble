package multisigwallet

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) generatePublicTaus(blind []byte) (bulletproofsShare *BulletproofsShare, err error) {
	fakeCommit, err := secp256k1.Commit(t.context, blind, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return
	}

	fakeBlind := make([]byte, 32)
	fakeBlind[0] = 1

	fakeCommonNonce := make([]byte, 32)

	_, _, publicTau1, publicTau2, err := secp256k1.BulletproofRangeproofProveMulti(t.context, nil, nil, nil, nil, nil,
		[]uint64{0}, [][]byte{fakeBlind}, []*secp256k1.Commitment{fakeCommit}, &secp256k1.GeneratorH, 64, fakeCommonNonce, blind, nil, nil)
	if err != nil {
		return
	}

	return &BulletproofsShare{PublicTau1: publicTau1.Hex(t.context), PublicTau2: publicTau2.Hex(t.context)}, nil
}

func (t *Wallet) computeTaux(blind []byte, assetBlind []byte, slate *Slate) (taux []byte, err error) {
	publicTau1s := make([]*secp256k1.PublicKey, 0)
	publicTau2s := make([]*secp256k1.PublicKey, 0)
	for _, participantData := range slate.ParticipantData {
		publicTau1Bytes, err := hex.DecodeString(participantData.BulletproofsShare.PublicTau1)
		if err != nil {
			return nil, err
		}

		_, publicTau1, err := secp256k1.EcPubkeyParse(t.context, publicTau1Bytes)
		if err != nil {
			return nil, err
		}
		publicTau1s = append(publicTau1s, publicTau1)

		publicTau2Bytes, err := hex.DecodeString(participantData.BulletproofsShare.PublicTau2)
		if err != nil {
			return nil, err
		}

		_, publicTau2, err := secp256k1.EcPubkeyParse(t.context, publicTau2Bytes)
		if err != nil {
			return nil, err
		}
		publicTau2s = append(publicTau2s, publicTau2)
	}

	_, sumPublicTau1, err := secp256k1.EcPubkeyCombine(t.context, publicTau1s)
	if err != nil {
		return nil, err
	}

	_, sumPublicTau2, err := secp256k1.EcPubkeyCombine(t.context, publicTau2s)
	if err != nil {
		return nil, err
	}

	commit, assetCommit, _, _, err := t.computeMultipartyCommit(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot computeMultipartyCommit")
		return
	}

	transactionID, err := slate.Transaction.ID.MarshalBinary()
	if err != nil {
		err = errors.Wrap(err, "cannot MarshalBinary")
		return
	}
	commonNonce := sha256.New().Sum(transactionID)[:32]

	_, taux, _, _, err = secp256k1.BulletproofRangeproofProveMulti(t.context, nil, nil, nil, sumPublicTau1, sumPublicTau2,
		[]uint64{uint64(slate.Amount)}, [][]byte{blind[:]}, []*secp256k1.Commitment{commit}, assetCommit, 64, commonNonce, blind, nil, nil)
	if err != nil {
		return
	}
	return
}

func (t *Wallet) aggregateProof(slate *Slate) (proof []byte, err error) {
	publicTau1s := make([]*secp256k1.PublicKey, 0)
	publicTau2s := make([]*secp256k1.PublicKey, 0)
	tauxs := make([][]byte, 0)
	for _, participantData := range slate.ParticipantData {
		publicTau1Bytes, err := hex.DecodeString(participantData.BulletproofsShare.PublicTau1)
		if err != nil {
			return nil, err
		}

		_, publicTau1, err := secp256k1.EcPubkeyParse(t.context, publicTau1Bytes)
		if err != nil {
			return nil, err
		}
		publicTau1s = append(publicTau1s, publicTau1)

		publicTau2Bytes, err := hex.DecodeString(participantData.BulletproofsShare.PublicTau2)
		if err != nil {
			return nil, err
		}

		_, publicTau2, err := secp256k1.EcPubkeyParse(t.context, publicTau2Bytes)
		if err != nil {
			return nil, err
		}
		publicTau2s = append(publicTau2s, publicTau2)

		taux, err := hex.DecodeString(participantData.BulletproofsShare.Taux)
		if err != nil {
			return nil, err
		}
		tauxs = append(tauxs, taux)
	}

	_, sumPublicTau1, err := secp256k1.EcPubkeyCombine(t.context, publicTau1s)
	if err != nil {
		return nil, err
	}

	_, sumPublicTau2, err := secp256k1.EcPubkeyCombine(t.context, publicTau2s)
	if err != nil {
		return nil, err
	}

	sumTauxs, err := secp256k1.BlindSum(t.context, tauxs, nil)
	if err != nil {
		return nil, err
	}

	commit, assetCommit, _, _, err := t.computeMultipartyCommit(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot computeMultipartyCommit")
		return
	}

	transactionID, err := slate.Transaction.ID.MarshalBinary()
	if err != nil {
		err = errors.Wrap(err, "cannot MarshalBinary")
		return
	}
	commonNonce := sha256.New().Sum(transactionID)[:32]

	// mandatory within implementation, but not necessary for algorithm
	fakeBlind := make([]byte, 32)
	fakeBlind[0] = 1

	proof, _, _, _, err = secp256k1.BulletproofRangeproofProveMulti(t.context, nil, nil, sumTauxs[:], sumPublicTau1, sumPublicTau2,
		[]uint64{uint64(slate.Amount)}, [][]byte{fakeBlind}, []*secp256k1.Commitment{commit}, assetCommit, 64, commonNonce, fakeBlind, nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot BulletproofRangeproofProveMulti")
		return
	}
	return
}
