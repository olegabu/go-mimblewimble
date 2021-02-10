package wallet

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"

	"github.com/pkg/errors"
)

const mnemonicPassword = ""
const masterKeyFilename = "master.key"
const entropyBitSize = 128

func (t *Wallet) Nonce(context *secp256k1.Context) (rnd32 [32]byte, err error) {
	seed32 := secp256k1.Random256()
	rnd32, err = secp256k1.AggsigGenerateSecureNonce(context, seed32[:])
	return
}

func (t *Wallet) masterKeyPath() string {
	return filepath.Join(t.persistDir, masterKeyFilename)
}

func (t *Wallet) putMasterKey(masterKey *bip32.Key) error {
	masterKeyBytes, err := masterKey.Serialize()
	if err != nil {
		return errors.Wrap(err, "cannot Serialize masterKey")
	}

	err = ioutil.WriteFile(t.masterKeyPath(), masterKeyBytes, 0600)
	if err != nil {
		return errors.Wrap(err, "cannot WriteFile with masterKey")
	}

	return nil
}

func (t *Wallet) masterKeyFromFile() (masterKey *bip32.Key, err error) {
	masterKeyBytes, err := ioutil.ReadFile(t.masterKeyPath())
	if err != nil {
		return nil, errors.Wrap(err, "cannot ReadFile with masterKey")
	}

	masterKey, err = bip32.Deserialize(masterKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot Deserialize masterKey")
	}

	return
}

func (t *Wallet) newMasterKey() (mnemonic string, err error) {
	//seed, err := bip32.NewSeed()
	//if err != nil {
	//	return nil, errors.Wrap(err, "cannot get NewSeed from bip32")
	//}

	// Generate a mnemonic for memorization or user-friendly seeds
	entropy, err := bip39.NewEntropy(entropyBitSize)
	if err != nil {
		err = errors.Wrap(err, "cannot get NewEntropy from bip39")
		return
	}

	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		err = errors.Wrap(err, "cannot get NewMnemonic from entropy")
		return
	}

	err = t.masterKeyFromMnemonic(mnemonic)
	if err != nil {
		err = errors.Wrap(err, "cannot create masterKeyFromMnemonic")
	}

	return
}

func (t *Wallet) masterKeyFromMnemonic(mnemonic string) (err error) {
	seed := bip39.NewSeed(mnemonic, mnemonicPassword)

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		err = errors.Wrap(err, "cannot get NewMasterKey from seed")
		return
	}

	err = t.putMasterKey(masterKey)
	if err != nil {
		err = errors.Wrap(err, "cannot putMasterKey")
		return
	}

	t.masterKey = masterKey

	return
}

func (t *Wallet) masterKeyExists() (ret bool) {
	_, err := t.masterKeyFromFile()
	if err != nil {
		return false
	}
	return true
}

func (t *Wallet) readMasterKey() (err error) {
	masterKey, err := t.masterKeyFromFile()
	if err != nil {
		return errors.Wrap(err, "cannot masterKeyFromFile")
	}

	t.masterKey = masterKey

	return
}

func (t *Wallet) newMasterKeyIfDoesntExist() (err error) {
	if !t.masterKeyExists() {
		mnemonic, err := t.newMasterKey()
		if err != nil {
			return errors.Wrap(err, "cannot newMasterKey")
		}
		fmt.Println("created new master secret key with mnemonic: ", mnemonic)
	} else {
		err := t.readMasterKey()
		if err != nil {
			return errors.Wrap(err, "cannot readMasterKey")
		}
	}

	return
}

func (t *Wallet) InitMasterKey(mnemonic string) (createdMnemonic string, err error) {
	if t.masterKeyExists() {
		if len(mnemonic) > 0 {
			err = errors.New("don't want to overwrite existing key by one created from your mnemonic, remove existing first")
			return
		} else {
			err = t.readMasterKey()
			if err != nil {
				err = errors.Wrap(err, "cannot read master key")
				return
			}
		}
	} else {
		if len(mnemonic) == 0 {
			createdMnemonic, err = t.newMasterKey()
			if err != nil {
				err = errors.Wrap(err, "cannot create master key")
				return
			}
		} else {
			err = t.masterKeyFromMnemonic(mnemonic)
			if err != nil {
				err = errors.Wrap(err, "cannot create master key from mnemonic")
				return
			}
		}
	}

	return
}

func (t *Wallet) NewSecret(context *secp256k1.Context) (secret [32]byte, index uint32, err error) {
	index, err = t.db.NextIndex()
	if err != nil {
		return [32]byte{}, 0, errors.Wrap(err, "cannot get NextIndex from db")
	}

	secret, err = t.Secret(context, index)
	if err != nil {
		return [32]byte{}, 0, errors.Wrap(err, "cannot get secretFromIndex")
	}

	return
}

func (t *Wallet) Secret(context *secp256k1.Context, index uint32) (secret [32]byte, err error) {
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
