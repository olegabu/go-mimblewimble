package vss

import (
	"math/big"

	vss "github.com/AllFi/go-pedersen-vss"
	"github.com/AllFi/go-pedersen-vss/types"
	"github.com/pkg/errors"
)

type Share struct {
	VerifiableShare string `json:"share,omitempty"`
	Commitment      string `json:"commitment,omitempty"`
}

func ShareBlind(n int, k int, blind []byte) (shares []Share, err error) {
	secret := types.NewFn()
	secret.SetBytes(blind)

	indices := getIndices(n)
	vshares, c, e := vss.VShareSecret(indices, types.GeneratorH(), secret, k)
	if e != nil {
		err = errors.Wrap(e, "cannot VShareSecret")
		return
	}

	for _, vshare := range vshares {
		share := Share{VerifiableShare: vshare.Hex(), Commitment: c.Hex()}
		shares = append(shares, share)
	}
	return
}

func VerifyShare(share Share) (isValid bool, err error) {
	c := &types.Commitment{}
	e := c.SetHex(share.Commitment)
	if e != nil {
		err = errors.Wrap(e, "cannot parse Commitment")
		return
	}

	vs := &types.VerifiableShare{}
	e = vs.SetHex(share.VerifiableShare)
	if e != nil {
		err = errors.Wrap(e, "cannot parse VerifiableShare")
		return
	}

	if !vss.IsValid(types.GeneratorH(), c, vs) {
		return false, nil
	}
	return true, nil
}

func OpenBlind(shares []string) (blind []byte, err error) {
	verifiableShares := make([]types.VerifiableShare, 0)
	for _, share := range shares {
		verifiableShare := types.VerifiableShare{}
		e := verifiableShare.SetHex(share)
		if e != nil {
			err = errors.Wrap(e, "cannot parse VerifiableShare")
			return
		}
		verifiableShares = append(verifiableShares, verifiableShare)
	}
	return vss.Open(verifiableShares).Bytes(), nil
}

func getIndices(n int) []types.Fn {
	indices := make([]types.Fn, n)
	for i := range indices {
		indices[i] = types.Fn{Int: big.NewInt(int64(i + 1))}
	}
	return indices
}
