package bulletproof

import (
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

// Share is a shared data for Bulletproofs MPC
type Share struct {
	PublicTau1 string `json:"public_tau1"`
	PublicTau2 string `json:"public_tau2"`
	Taux       string `json:"taux"`
}

func GeneratePublicTaus(context *secp256k1.Context, blind []byte) (bulletproofsShare *Share, err error) {
	fakeBlind := [32]byte{1}
	fakeCommonNonce := make([]byte, 32)
	fakeCommit, err := secp256k1.Commit(context, fakeBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot create fakeCommit")
		return
	}

	_, _, publicTau1, publicTau2, err := secp256k1.BulletproofRangeproofProveMulti(context, nil, nil, nil, nil, nil,
		[]uint64{0}, [][]byte{fakeBlind[:]}, []*secp256k1.Commitment{fakeCommit}, &secp256k1.GeneratorH, 64, fakeCommonNonce, blind, nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot process first step of bulletproof mpc protocol")
		return
	}

	return &Share{PublicTau1: publicTau1.Hex(context), PublicTau2: publicTau2.Hex(context)}, nil
}

func ComputeTaux(
	context *secp256k1.Context,
	amount uint64,
	blind []byte,
	assetBlind []byte,
	commit *secp256k1.Commitment,
	assetCommit *secp256k1.Generator,
	sumPublicTau1 *secp256k1.PublicKey,
	sumPublicTau2 *secp256k1.PublicKey,
	commonNonce []byte,
) (
	taux []byte,
	err error,
) {
	_, taux, _, _, err = secp256k1.BulletproofRangeproofProveMulti(context, nil, nil, nil, sumPublicTau1, sumPublicTau2,
		[]uint64{amount}, [][]byte{blind[:]}, []*secp256k1.Commitment{commit}, assetCommit, 64, commonNonce, blind, nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot process second step of bulletproof mpc protocol")
		return
	}
	return
}

func AggregateProof(
	context *secp256k1.Context,
	amount uint64,
	commit *secp256k1.Commitment,
	assetCommit *secp256k1.Generator,
	sumPublicTau1 *secp256k1.PublicKey,
	sumPublicTau2 *secp256k1.PublicKey,
	sumTaux [32]byte,
	commonNonce []byte,
) (
	proof []byte,
	err error,
) {
	fakeBlind := [32]byte{1}
	proof, _, _, _, err = secp256k1.BulletproofRangeproofProveMulti(context, nil, nil, sumTaux[:], sumPublicTau1, sumPublicTau2,
		[]uint64{amount}, [][]byte{fakeBlind[:]}, []*secp256k1.Commitment{commit}, assetCommit, 64, commonNonce, fakeBlind[:], nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot process third step of bulletproof mpc protocol")
		return
	}
	return
}
