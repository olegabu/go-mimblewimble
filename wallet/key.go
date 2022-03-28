package wallet

import (
	"crypto/sha256"
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"io/ioutil"
	"path/filepath"

	"errors"
)

const mnemonicPassword = ""
const masterKeyFilename = "master.key"
const entropyBitSize = 128

func hashSha256(data []byte) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (t *Wallet) nonce() (rnd32 [32]byte, err error) {
	seed32 := secp256k1.Random256()
	//rnd32, err = secp256k1.AggsigGenerateSecureNonce(t.context, seed32[:])
	hash, err := hashSha256(seed32[:])
	if err != nil { return }
	copy(rnd32[:], hash)
	return
}

func (t *Wallet) masterKeyPath() string {
	return filepath.Join(t.persistDir, masterKeyFilename)
}

func (t *Wallet) putMasterKey(masterKey *bip32.Key) error {
	masterKeyBytes, err := masterKey.Serialize()
	if err != nil {
		return fmt.Errorf("%w: cannot Serialize masterKey", err)
	}

	err = ioutil.WriteFile(t.masterKeyPath(), masterKeyBytes, 0600)
	if err != nil {
		return fmt.Errorf("%w: cannot WriteFile with masterKey", err)
	}

	return nil
}

func (t *Wallet) masterKeyFromFile() (masterKey *bip32.Key, err error) {
	masterKeyBytes, err := ioutil.ReadFile(t.masterKeyPath())
	if err != nil {
		return nil, fmt.Errorf("%w: cannot ReadFile with masterKey", err)
	}

	masterKey, err = bip32.Deserialize(masterKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot Deserialize masterKey", err)
	}

	return
}

func (t *Wallet) newMasterKey() (mnemonic string, err error) {
	//seed, err := bip32.NewSeed()
	//if err != nil {
	//	return nil, fmt.Errorf("%w: cannot get NewSeed from bip32", err)
	//}

	// Generate a mnemonic for memorization or user-friendly seeds
	entropy, err := bip39.NewEntropy(entropyBitSize)
	if err != nil {
		err = fmt.Errorf("%w: cannot get NewEntropy from bip39", err)
		return
	}

	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		err = fmt.Errorf("%w: cannot get NewMnemonic from entropy", err)
		return
	}

	err = t.masterKeyFromMnemonic(mnemonic)
	if err != nil {
		err = fmt.Errorf("%w: cannot create masterKeyFromMnemonic", err)
	}

	return
}

func (t *Wallet) masterKeyFromMnemonic(mnemonic string) (err error) {
	seed := bip39.NewSeed(mnemonic, mnemonicPassword)

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		err = fmt.Errorf("%w: cannot get NewMasterKey from seed", err)
		return
	}

	err = t.putMasterKey(masterKey)
	if err != nil {
		err = fmt.Errorf("%w: cannot putMasterKey", err)
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
		return fmt.Errorf("%w: cannot masterKeyFromFile", err)
	}

	t.masterKey = masterKey

	return
}

func (t *Wallet) newMasterKeyIfDoesntExist() (err error) {
	if !t.masterKeyExists() {
		mnemonic, err := t.newMasterKey()
		if err != nil {
			return fmt.Errorf("%w: cannot newMasterKey", err)
		}
		fmt.Println("created new master secret key with mnemonic: ", mnemonic)
	} else {
		err := t.readMasterKey()
		if err != nil {
			return fmt.Errorf("%w: cannot readMasterKey", err)
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
				err = fmt.Errorf("%w: cannot read master key", err)
				return
			}
		}
	} else {
		if len(mnemonic) == 0 {
			createdMnemonic, err = t.newMasterKey()
			if err != nil {
				err = fmt.Errorf("%w: cannot create master key", err)
				return
			}
		} else {
			err = t.masterKeyFromMnemonic(mnemonic)
			if err != nil {
				err = fmt.Errorf("%w: cannot create master key from mnemonic", err)
				return
			}
		}
	}

	return
}

func (t *Wallet) newSecret() (secret [32]byte, index uint32, err error) {
	index, err = t.db.NextIndex()
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("%w: cannot get NextIndex from db", err)
	}

	secret, err = t.secret(index)
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("%w: cannot get secretFromIndex", err)
	}

	return
}

func (t *Wallet) secret(index uint32) (secret [32]byte, err error) {
	childKey, err := t.masterKey.NewChildKey(index)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: cannot get NewChildKey", err)
	}

	childKeyBytes, err := childKey.Serialize()
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: cannot Serialize childKey", err)
	}

	//secret, err = secp256k1.AggsigGenerateSecureNonce(t.context, childKeyBytes)
	hash, err := hashSha256(childKeyBytes)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: cannot generate secret from childKeyBytes", err)
	}
	copy(secret[:], hash)

	return
}
