package multisigwallet

import (
	"math/big"

	vss "github.com/AllFi/go-pedersen-vss"
	"github.com/AllFi/go-pedersen-vss/types"
	"github.com/pkg/errors"
)

type VerifiableBlindShares struct {
	ParticipantID    string            `json:"participant_id,omitempty"`
	VerifiableShares []VerifiableShare `json:"verifiable_shares,omitempty"`
}

type VerifiableShare struct {
	VerifiableShare string `json:"share,omitempty"`
	Commitment      string `json:"commitment,omitempty"`
}

func (t *Wallet) generateAndShareBlinds(participantIDs []string, k int, blindsCount int) (blindIndexes []uint32, shares []VerifiableBlindShares, err error) {
	n := len(participantIDs)

	for _, participantID := range participantIDs {
		vbs := VerifiableBlindShares{ParticipantID: participantID, VerifiableShares: make([]VerifiableShare, 0)}
		shares = append(shares, vbs)
	}

	h := types.GeneratorH()
	for i := 0; i < blindsCount; i++ {
		blind, blindIndex, e := t.newSecret()
		if e != nil {
			err = errors.Wrap(e, "cannot generate blind")
			return
		}

		blindIndexes = append(blindIndexes, blindIndex)

		secret := types.NewFn()
		secret.SetBytes(blind[:])

		indices := getIndices(n)
		vshares, c, e := vss.VShareSecret(indices, h, secret, k)
		if e != nil {
			err = errors.Wrap(e, "cannot VShareSecret")
			return
		}

		for i, vshare := range vshares {
			share := VerifiableShare{VerifiableShare: vshare.Hex(), Commitment: c.Hex()}
			shares[i].VerifiableShares = append(shares[i].VerifiableShares, share)
		}
	}
	return
}

func (t *Wallet) verifyShares(shares VerifiableBlindShares) (isValid bool, err error) {
	h := types.GeneratorH()
	for _, share := range shares.VerifiableShares {
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

		if !vss.IsValid(h, c, vs) {
			return false, nil
		}
	}
	return true, nil
}

func (t *Wallet) openBlind(shares []string) (blind []byte, err error) {
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
