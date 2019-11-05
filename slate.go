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

type WalletOutput struct {
	core.Output
	Blind [32]byte
	Value uint64
}

func CreateSlate(amount uint64, walletInputs []WalletOutput) ([]byte, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
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
		return nil, errors.New("sum of sender input values is less than amount to send")
	}

	// create change output and remember its blinding factor

	changeOutput, changeBlind, err := output(context, change)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create changeOutput")
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
		return nil, errors.Wrap(err, "cannot sum input blinds")
	}

	// calculate public keys for sum of sender's blinding factors and random nonce

	publicBlindExcess, err := serializedPubKey(context, sumBlinds)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	nonce, err := random()
	if err != nil {
		return nil, errors.Wrap(err, "cannot get random for nonce")
	}

	publicNonce, err := serializedPubKey(context, nonce)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create publicNonce")
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
		return nil, errors.Wrap(err, "cannot marshal slate to json")
	}

	return slateBytes, nil
}

func CreateResponse(slateBytes []byte) ([]byte, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	var slate = libwallet.Slate{}

	err = json.Unmarshal(slateBytes, slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to slate")
	}

	// create receiver output and remember its blinding factor

	/*output, blind, err := output(context, uint64(slate.Amount))
	if err != nil {
		return nil, errors.Wrap(err, "cannot create receiver output")
	}

	// calculate public keys for sum of sender's blinding factors and random nonce

	res, publicBlindExcess, err := secp256k1.EcPubkeyCreate(context, blind[:])
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot create publicBlindExcess")
	}

	nonce, err := random()
	if err != nil {
		return nil, errors.Wrap(err, "cannot get random for nonce")
	}

	res, publicNonce, err := secp256k1.EcPubkeyCreate(context, nonce[:])
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot create publicNonce")
	}

	msg := kernelSignatureMessage(slate.Transaction.Body.Kernels[0])*/

	//TODO find secp256k1 library function to create a partial Schnorr signature, this does not take nonce only seckey
	// grin uses secp256k1_aggsig_sign_single which I cannot find
	// https://github.com/mimblewimble/grin/blob/2ee8d06d483649647e39a172693a7522496b8a27/core/src/libtx/aggsig.rs#L98
	// func SchnorrsigSign(
	//	context *Context,
	//	hash32 [32]byte,
	//	seckey [32]byte,
	//	//	noncefunc *NonceGenerator,
	//	//	nonceseed []byte,
	//)
	/*schnorrChallenge, err := schnorrChallenge(context, msg, publicBlindExcess, publicNonce, slate.ParticipantData)
	if err != nil {
		return nil, errors.Wrap(err, "cannot calculate schnorrChallenge")
	}

	secp256k1.SchnorrsigSign()*/

	//TODO add output, Schnorr signature and public blind and public nonce to receiver participant data in the slate

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal slate to json")
	}

	return slateBytes, nil

}

func CreateTransaction(slateBytes []byte) ([]byte, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	var slate = libwallet.Slate{}

	err = json.Unmarshal(slateBytes, slate)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal json to slate")
	}

	tx := core.Transaction{}

	//TODO

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal transaction to json")
	}

	return txBytes, nil

}

func output(context *secp256k1.Context, value uint64) (core.Output, [32]byte, error) {
	blind, err := random()
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

func serializedPubKey(context *secp256k1.Context, sk [32]byte) (string, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(context, sk[:])
	if res != 1 || err != nil {
		return "", errors.Wrapf(err, "cannot create publicBlindExcess")
	}

	res, pkBytes, err := secp256k1.EcPubkeySerialize(context, pk, uint(compressedPubKeyFlag))
	if res != 1 || err != nil {
		return "", errors.Wrapf(err, "cannot serialize publicBlindExcess")
	}

	pkString := hex.EncodeToString(pkBytes)

	return pkString, nil
}

func schnorrChallenge(context *secp256k1.Context, msg []byte, publicBlindExcess *secp256k1.PublicKey, publicNonce *secp256k1.PublicKey, participantData []libwallet.ParticipantData) ([]byte, error) {
	senderData := participantData[0]

	senderPublicBlindExcessBytes, err := hex.DecodeString(senderData.PublicBlindExcess)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot decode senderData.PublicBlindExcess")
	}

	res, senderPublicBlindExcess, err := secp256k1.EcPubkeyParse(context, senderPublicBlindExcessBytes)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot parse senderPublicBlindExcessBytes")
	}

	senderPublicNonceBytes, err := hex.DecodeString(senderData.PublicNonce)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot decode senderData.PublicNonce")
	}

	res, senderPublicNonce, err := secp256k1.EcPubkeyParse(context, senderPublicNonceBytes)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot parse senderPublicNonceExcessBytes")
	}

	res, sumPublicBlinds, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicBlindExcess, publicBlindExcess})
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot sum public blinds")
	}

	res, sumPublicBlindsBytes, err := secp256k1.EcPubkeySerialize(context, sumPublicBlinds, compressedPubKeyFlag)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot serialize public blinds")
	}

	res, sumPublicNonces, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicNonce, publicNonce})
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot sum public nonces")
	}

	res, sumPublicNoncesBytes, err := secp256k1.EcPubkeySerialize(context, sumPublicNonces, compressedPubKeyFlag)
	if res != 1 || err != nil {
		return nil, errors.Wrapf(err, "cannot serialize public blinds")
	}

	hash, _ := blake2b.New256(nil)
	hash.Write(msg)
	hash.Write(sumPublicNoncesBytes)
	hash.Write(sumPublicBlindsBytes)

	return hash.Sum(nil), nil
}
