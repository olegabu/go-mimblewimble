package multisig

import (
	"github.com/olegabu/go-secp256k1-zkp"
)

type Wallet interface {
	Secret(index uint32) (secret [32]byte, err error)
	NewSecret() (secret [32]byte, index uint32, err error)
	Nonce() (rnd32 [32]byte, err error)
	GetContext() *secp256k1.Context
}
