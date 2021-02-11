package types

import (
	"crypto/sha256"

	"github.com/olegabu/go-secp256k1-zkp"
)

type TestSecretGenerator struct {
	currentIndex uint32
}

func NewTestSecretGenerator() (secretGenerator SecretGenerator, err error) {
	return &TestSecretGenerator{0}, nil
}

func (w *TestSecretGenerator) Secret(context *secp256k1.Context, index uint32) (secret [32]byte, err error) {
	return sha256.Sum256(i32tob(index)), nil
}

func (w *TestSecretGenerator) NewSecret(context *secp256k1.Context) (secret [32]byte, index uint32, err error) {
	w.currentIndex++
	secret, _ = w.Secret(context, w.currentIndex)
	return secret, w.currentIndex, nil
}

func (w *TestSecretGenerator) Nonce(context *secp256k1.Context) (rnd32 [32]byte, err error) {
	return secp256k1.Random256(), nil
}

func i32tob(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}
