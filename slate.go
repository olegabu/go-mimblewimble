package mw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

const compressedPubKeyFlag = (1 << 1) | (1 << 8)

var seed = [32]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

type WalletOutput struct {
	core.Output
	Blind [32]byte
	Value uint64
}

func CreateSlate(amount uint64, walletInputs []WalletOutput) ([]byte, []byte, []byte, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	// loop thru inputs to calculate change and collect input blinding factors

	var sumInputValues uint64
	negBlinds := make([][32]byte, 0)
	inputs := make([]core.Input, 0)

	for _, walletInput := range walletInputs {
		sumInputValues += walletInput.Value

		negBlinds = append(negBlinds, walletInput.Blind)

		inputs = append(inputs, core.Input{
			Features: walletInput.Features,
			Commit:   walletInput.Commit,
		})
	}

	change := sumInputValues - amount
	if change < 0 {
		return nil, nil, nil, errors.New("sum of sender input values is less than amount to send")
	}

	// create change output and remember its blinding factor

	changeOutput, changeBlind, err := output(context, change)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "cannot create changeOutput")
	}

	// combine input (negative) and output (positive, just one: change) blinding factors

	blinds := make([][32]byte, 0)
	posBlinds := make([][32]byte, 0)
	posBlinds = append(posBlinds, changeBlind)
	blinds = append(blinds, posBlinds...)
	blinds = append(blinds, negBlinds...)

	// sum up input and change blinding factors

	status, sumBlinds, err := secp256k1.BlindSum(context, blinds, len(posBlinds))
	if !status || err != nil {
		return nil, nil, nil, errors.Wrap(err, "cannot sum input blinds")
	}

	// calculate public keys for sum of sender's blinding factors and random nonce

	publicBlindExcess, err := stringPubKeyFromSecretKey(context, sumBlinds)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	nonce, err := secret()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "cannot get random for nonce")
	}

	publicNonce, err := stringPubKeyFromSecretKey(context, nonce)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "cannot create publicNonce")
	}

	// put these all into a slate and marshal it to json

	//TODO calculate transaction offset

	slate := &libwallet.Slate{
		VersionInfo: libwallet.VersionCompatInfo{
			Version:            2,
			OrigVersion:        2,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 2,
		ID:              uuid.New(),
		Transaction: core.Transaction{
			Offset: "",
			Body: core.TransactionBody{
				Inputs:  inputs,
				Outputs: []core.Output{changeOutput},
				Kernels: make([]core.TxKernel, 1),
			},
		},
		Amount:     core.Uint64(amount),
		Fee:        0,
		Height:     0,
		LockHeight: 0,
		ParticipantData: []libwallet.ParticipantData{libwallet.ParticipantData{
			ID:                0,
			PublicBlindExcess: publicBlindExcess,
			PublicNonce:       publicNonce,
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
		}},
	}

	slateBytes, err := json.Marshal(slate)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "cannot marshal slate to json")
	}

	return slateBytes, sumBlinds[:], nonce[:], nil
}

func CreateResponse(slateBytes []byte) ([]byte, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	var slate = libwallet.Slate{}

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to slate")
	}

	// create receiver output and remember its blinding factor

	output, blind, err := output(context, uint64(slate.Amount))
	if err != nil {
		return nil, errors.Wrap(err, "cannot create receiver output")
	}

	// calculate public key for receiver output blinding factor

	res, publicBlindExcess, err := secp256k1.EcPubkeyCreate(context, blind[:])
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot create publicBlindExcess")
	}

	publicBlindExcessString, err := pubKeyToString(context, publicBlindExcess)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create publicBlindExcessString")
	}

	// choose sender nonce and calculate its public key

	nonce, err := secret()
	if err != nil {
		return nil, errors.Wrap(err, "cannot get random for nonce")
	}

	res, publicNonce, err := secp256k1.EcPubkeyCreate(context, nonce[:])
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot create publicNonce")
	}

	publicNonceString, err := pubKeyToString(context, publicNonce)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create publicNonceString")
	}

	// parse out message to use as part of the Schnorr challenge

	msg := kernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// parse out sender's public blinds and nonces

	senderPublicBlindExcess, err := stringToPubKey(context, slate.ParticipantData[0].PublicBlindExcess)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get senderPublicBlindExcess")
	}

	senderPublicNonce, err := stringToPubKey(context, slate.ParticipantData[0].PublicNonce)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get senderPublicNonce")
	}

	// calculate Schnorr challenge

	schnorrChallenge, err := schnorrChallenge(context, msg, senderPublicBlindExcess, senderPublicNonce, publicBlindExcess, publicNonce)
	if err != nil {
		return nil, errors.Wrap(err, "cannot calculate schnorrChallenge")
	}

	// this seed is not used, we pass it to satisfy the underlying C function
	//seed, _ := random()

	// calculate receiver's partial Schnorr signature

	schnorrSig, err := secp256k1.AggsigSignSingle(context, schnorrChallenge, blind[:], nonce[:], nil, nil, nil, nil, seed[:])
	if err != nil {
		return nil, errors.Wrap(err, "cannot calculate schnorrSig")
	}

	schnorrSigString := hex.EncodeToString(schnorrSig)

	slate.ParticipantData = append(slate.ParticipantData, libwallet.ParticipantData{
		ID:                1,
		PublicBlindExcess: publicBlindExcessString,
		PublicNonce:       publicNonceString,
		PartSig:           &schnorrSigString,
		Message:           nil,
		MessageSig:        nil,
	})

	slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, output)

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal slate to json")
	}

	return slateBytes, nil
}

func CreateTransaction(slateBytes []byte, senderBlind []byte, senderNonce []byte) ([]byte, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	var slate = libwallet.Slate{}

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to slate")
	}

	// parse out message to use as part of the Schnorr challenge

	msg := kernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// parse out public blinds and nonces for both sender and receiver from the slate
	//TODO should the sender trust its public keys in receiver's response or use its own, remembered from construction of the slate?

	senderPublicBlindExcess, err := stringToPubKey(context, slate.ParticipantData[0].PublicBlindExcess)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get senderPublicBlindExcess")
	}

	senderPublicNonce, err := stringToPubKey(context, slate.ParticipantData[0].PublicNonce)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get senderPublicNonce")
	}

	receiverPublicBlindExcess, err := stringToPubKey(context, slate.ParticipantData[1].PublicBlindExcess)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get receiverPublicBlindExcess")
	}

	receiverPublicNonce, err := stringToPubKey(context, slate.ParticipantData[1].PublicNonce)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get receiverPublicNonce")
	}

	// calculate Schnorr challenge

	schnorrChallenge, err := schnorrChallenge(context, msg, senderPublicBlindExcess, senderPublicNonce, receiverPublicBlindExcess, receiverPublicNonce)
	if err != nil {
		return nil, errors.Wrap(err, "cannot calculate schnorrChallenge")
	}

	// verify receiver's partial signature

	receiverPartialSigBytes, err := hex.DecodeString(*slate.ParticipantData[1].PartSig)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse receiverPartialSig from hex")
	}

	status, err := secp256k1.AggsigVerifySingle(context, receiverPartialSigBytes, schnorrChallenge, nil, receiverPublicBlindExcess, nil, nil, false)
	if err != nil {
		return nil, errors.Wrap(err, "cannot verify receiver partial signature")
	}
	if !status {
		return nil, errors.New("receiver partial signature is invalid")
	}

	// calculate receiver's partial Schnorr signature

	// this seed is not used, we pass it to satisfy the underlying C function
	//seed, _ := random()

	senderPartialSigBytes, err := secp256k1.AggsigSignSingle(context, schnorrChallenge, senderBlind, senderNonce, nil, nil, nil, nil, seed[:])
	if err != nil {
		return nil, errors.Wrap(err, "cannot calculate schnorrSig")
	}

	// sum sender and receiver public nonces for the second half of the excess signature

	res, sumPublicNonces, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot sum public nonces")
	}

	// sum sender and receiver partial signatures and append sum of public nonces to form whole two part excess signature

	excessSig, err := secp256k1.AggsigAddSignaturesSingle(context, [][]byte{senderPartialSigBytes, receiverPartialSigBytes}, sumPublicNonces)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create excess signature")
	}

	excessSigString := hex.EncodeToString(excessSig)

	// calculate kernel excess as a sum of sender and receiver public blinds

	res, excess, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicBlindExcess, receiverPublicBlindExcess})
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot sum public blinds")
	}

	excessString, err := pubKeyToString(context, excess)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot convert excess to string")
	}

	tx := slate.Transaction

	tx.Body.Kernels[0].Excess = excessString
	tx.Body.Kernels[0].ExcessSig = excessSigString

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal transaction to json")
	}

	return txBytes, nil
}

func output(context *secp256k1.Context, value uint64) (core.Output, [32]byte, error) {
	blind, err := secret()
	if err != nil {
		return core.Output{}, blind, errors.Wrap(err, "cannot get random for blind")
	}

	status, commitment, err := secp256k1.Commit(context, blind, value, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if !status || err != nil {
		return core.Output{}, blind, errors.Wrapf(err, "cannot create commitment to value")
	}

	//TODO create bullet proof to value

	output := core.Output{
		Features: core.PlainOutput,
		Commit:   commitment.Hex(),
		Proof:    "",
	}

	return output, blind, nil
}

func random() ([32]byte, error) {
	s := make([]byte, 32)
	l, err := rand.Read(s)

	var r [32]byte
	copy(r[:], s[:32])

	if l != 32 || err != nil {
		return r, errors.New("cannot Rand256")
	}

	return r, nil
}

func secret() ([32]byte, error) {
	return random()
}

func stringPubKeyFromSecretKey(context *secp256k1.Context, sk [32]byte) (string, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(context, sk[:])
	if res != 1 || err != nil {
		return "", errors.Wrapf(err, "cannot create PublicKey")
	}

	return pubKeyToString(context, pk)
}

func pubKeyToString(context *secp256k1.Context, pk *secp256k1.PublicKey) (string, error) {
	res, pkBytes, err := secp256k1.EcPubkeySerialize(context, pk, uint(compressedPubKeyFlag))
	if res != 1 || err != nil {
		return "", errors.Wrapf(err, "cannot serialize PublicKey")
	}

	pkString := hex.EncodeToString(pkBytes)

	return pkString, nil
}

func stringToPubKey(context *secp256k1.Context, s string) (*secp256k1.PublicKey, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot decode public key from hex string")
	}

	res, pk, err := secp256k1.EcPubkeyParse(context, bytes)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot parse public key from bytes")
	}

	return pk, nil
}

func stringToPubKeyBytes(context *secp256k1.Context, s string) ([]byte, error) {
	pk, err := stringToPubKey(context, s)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot convert string to PubKey")
	}

	res, bytes, err := secp256k1.EcPubkeySerialize(context, pk, compressedPubKeyFlag)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot serialize PubKey")
	}

	return bytes, nil
}

func sumPubKeysToBytes(context *secp256k1.Context, pubKeys []*secp256k1.PublicKey) ([]byte, error) {
	res, sumPubKeys, err := secp256k1.EcPubkeyCombine(context, pubKeys)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot sum public keys")
	}

	res, sumPubKeysBytes, err := secp256k1.EcPubkeySerialize(context, sumPubKeys, compressedPubKeyFlag)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot serialize public blinds")
	}

	return sumPubKeysBytes, nil
}

//senderPublicBlindExcess, err := stringToPubKey(context, senderPublicBlindExcess)
//if err != nil {
//return nil, errors.Wrapf(err, "cannot get senderPublicBlindExcess")
//}

//senderPublicNonce, err := stringToPubKey(context, senderData.PublicNonce)
//if err != nil {
//return nil, errors.Wrapf(err, "cannot get senderPublicNonce")
//}

func schnorrChallenge(context *secp256k1.Context, msg []byte, senderPublicBlindExcess *secp256k1.PublicKey, senderPublicNonce *secp256k1.PublicKey, receiverPublicBlindExcess *secp256k1.PublicKey, receiverPublicNonce *secp256k1.PublicKey) ([]byte, error) {
	hash, _ := blake2b.New256(nil)
	hash.Write(msg)

	if senderPublicBlindExcess != nil && senderPublicNonce != nil && receiverPublicBlindExcess != nil && receiverPublicNonce != nil {
		sumPublicBlindsBytes, err := sumPubKeysToBytes(context, []*secp256k1.PublicKey{senderPublicBlindExcess, receiverPublicBlindExcess})
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get sumPublicBlindsBytes")
		}

		sumPublicNoncesBytes, err := sumPubKeysToBytes(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get sumPublicNoncesBytes")
		}

		hash.Write(sumPublicNoncesBytes)
		hash.Write(sumPublicBlindsBytes)
	}

	return hash.Sum(nil), nil
}
