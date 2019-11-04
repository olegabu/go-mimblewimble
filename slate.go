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
)

type WalletOutput struct {
	core.Output
	Blind [32]byte
	Value uint64
}

func newOutput(context *secp256k1.Context, value uint64) (core.Output, [32]byte, error) {
	blind, err := random()
	if err != nil {
		return core.Output{}, blind, errors.Wrap(err, "cannot get random for blind")
	}

	status, commitment, err := secp256k1.Commit(context, blind, value, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if !status || err != nil {
		return core.Output{}, blind, errors.Wrapf(err, "cannot create commitment to value")
	}

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

func createSerializedPubKey(context *secp256k1.Context, sk [32]byte) (string, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(context, sk[:])
	if res != 1 || err != nil {
		return "", errors.Wrapf(err, "cannot create publicBlindExcess")
	}

	compressed := (1 << 1) | (1 << 8)

	res, pkBytes, err := secp256k1.EcPubkeySerialize(context, pk, uint(compressed))
	if res != 1 || err != nil {
		return "", errors.Wrapf(err, "cannot serialize publicBlindExcess")
	}

	pkString := hex.EncodeToString(pkBytes)

	return pkString, nil
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

	changeOutput, changeBlind, err := newOutput(context, change)
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

	publicBlindExcess, err := createSerializedPubKey(context, sumBlinds)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	nonce, err := random()
	if err != nil {
		return nil, errors.Wrap(err, "cannot get random for nonce")
	}

	publicNonce, err := createSerializedPubKey(context, nonce)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create publicNonce")
	}

	// put these all into a slate and marshal it to json

	slate := &libwallet.Slate{
		VersionInfo: libwallet.VersionCompatInfo{
			Version:            2,
			OrigVersion:        2,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 2,
		ID:              uuid.New(),
		Transaction: core.Transaction{
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
