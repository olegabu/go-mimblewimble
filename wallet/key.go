package wallet

import (
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/tyler-smith/go-bip32"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
)

func (t *Wallet) nonce(context *secp256k1.Context) (rnd32 [32]byte, err error) {
	seed32 := secp256k1.Random256()
	rnd32, err = secp256k1.AggsigGenerateSecureNonce(context, seed32[:])
	return
}

func (t *Wallet) masterKeyFilename() string {
	return filepath.Join(t.persistDir, "master.key")
}

func (t *Wallet) putMasterKey(masterKey *bip32.Key) error {
	masterKeyBytes, err := masterKey.Serialize()
	if err != nil {
		return errors.Wrap(err, "cannot Serialize masterKey")
	}

	err = ioutil.WriteFile(t.masterKeyFilename(), masterKeyBytes, 0600)
	if err != nil {
		return errors.Wrap(err, "cannot WriteFile with masterKey")
	}

	return nil
}

func (t *Wallet) getMasterKey() (masterKey *bip32.Key, err error) {
	masterKeyBytes, err := ioutil.ReadFile(t.masterKeyFilename())
	if err != nil {
		return nil, errors.Wrap(err, "cannot ReadFile with masterKey")
	}

	masterKey, err = bip32.Deserialize(masterKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot Deserialize masterKey")
	}

	return
}

func (t *Wallet) createMasterKey() (masterKey *bip32.Key, err error) {
	seed, err := bip32.NewSeed()
	if err != nil {
		return nil, errors.Wrap(err, "cannot get NewSeed from bip32")
	}

	masterKey, err = bip32.NewMasterKey(seed)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get NewMasterKey from bip32")
	}

	err = t.putMasterKey(masterKey)
	if err != nil {
		return nil, errors.Wrap(err, "cannot putMasterKey")
	}

	return
}

func (t *Wallet) createMasterKeyIfDoesntExist() (err error) {
	masterKey, err := t.getMasterKey()
	if err != nil {
		masterKey, err = t.createMasterKey()
		if err != nil {
			return
		}
	}
	t.masterKey = masterKey

	return
}

func (t *Wallet) newSecret(context *secp256k1.Context) (secret [32]byte, index uint32, err error) {
	index, err = t.db.NextIndex()
	if err != nil {
		return [32]byte{}, 0, errors.Wrap(err, "cannot get NextIndex from db")
	}

	secret, err = t.secret(context, index)
	if err != nil {
		return [32]byte{}, 0, errors.Wrap(err, "cannot get secretFromIndex")
	}

	return
}

func (t *Wallet) secret(context *secp256k1.Context, index uint32) (secret [32]byte, err error) {
	childKey, err := t.masterKey.NewChildKey(index)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "cannot get NewChildKey")
	}

	childKeyBytes, err := childKey.Serialize()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "cannot Serialize childKey")
	}

	secret, err = secp256k1.AggsigGenerateSecureNonce(context, childKeyBytes)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "cannot AggsigGenerateSecureNonce from childKeyBytes")
	}

	return
}
