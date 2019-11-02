package go_mimblewimble

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	libgrin "github.com/blockcypher/libgrin/core"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

func VerifySignature(txBytes []byte) error {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	tx := &libgrin.Transaction{}

	err := json.Unmarshal(txBytes, tx)
	if err != nil {
		return errors.Wrap(err, "cannot unmarshal json with transaction")
	}

	excessSigBytes, err := hex.DecodeString(tx.Body.Kernels[0].ExcessSig)
	if err != nil {
		return errors.Wrap(err, "cannot decode ExcessSig")
	}

	excessBytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)
	if err != nil {
		return errors.Wrap(err, "cannot decode Excess")
	}

	status, excessCommitment, err := secp256k1.CommitmentParse(context, excessBytes[:])
	if !status || err != nil {
		return errors.Wrap(err, "CommitmentParse failed")
	}

	status, publicKey, err := secp256k1.CommitmentToPublicKey(context, excessCommitment)
	if !status || err != nil {
		return errors.Wrap(err, "CommitmentToPublicKey failed")
	}

	features := []byte{byte(0)}
	fee := make([]byte, 8)
	binary.BigEndian.PutUint64(fee, uint64(tx.Body.Kernels[0].Fee))
	hash, _ := blake2b.New256(nil)
	hash.Write(features)
	hash.Write(fee)
	msg := hash.Sum(nil)

	// _, serPubkey, _ := secp256k1.EcPubkeySerialize(context, pubkey)
	fmt.Printf("fee : %v\nfeatures: %v\nmsg:%v\nexcessBytes:%v\n", fee, features, hex.EncodeToString(msg), hex.EncodeToString(excessBytes))

	status, err = secp256k1.AggsigVerifySingle(
		context,
		excessSigBytes,
		msg,
		nil,
		publicKey,
		publicKey,
		nil,
		false,
	)
	if !status || err != nil {
		return errors.Wrap(err, "AggsigVerifySingle failed")
	}

	return nil
}
