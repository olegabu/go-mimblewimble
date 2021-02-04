package vss

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVSS(t *testing.T) {
	n := 10
	k := randRange(1, n-1)

	for i := 0; i < n; i++ {
		blind := randBlind()

		shares, err := ShareBlind(n, k, blind)
		assert.NoError(t, err)

		for _, share := range shares {
			ok, err := VerifyShare(share)
			assert.NoError(t, err)
			assert.True(t, ok)
		}

		verifiableShares := make([]string, 0)
		for i := 0; i < n; i++ {
			verifiableShares = append(verifiableShares, shares[i].VerifiableShare)
		}
		shuffle(verifiableShares)

		openedBlind, err := OpenBlind(verifiableShares[:k])
		assert.NoError(t, err)
		assert.Equal(t, blind[:], openedBlind)
	}
}

func shuffle(shares []string) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}

func randRange(lower, upper int) int {
	return rand.Intn(upper+1-lower) + lower
}

func randBlind() []byte {
	blind := [32]byte{}
	rand.Read(blind[:])
	return blind[:]
}
