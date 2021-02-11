package types

import (
	"github.com/olegabu/go-secp256k1-zkp"
)

type SecretGenerator interface {
	Secret(context *secp256k1.Context, index uint32) (secret [32]byte, err error)
	NewSecret(context *secp256k1.Context) (secret [32]byte, index uint32, err error)
	Nonce(context *secp256k1.Context) (rnd32 [32]byte, err error)
}
