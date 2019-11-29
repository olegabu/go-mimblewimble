package wallet

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	secp256k1 "github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

const compressedPubKeyFlag = (1 << 1) | (1 << 8)

var dummyseed = [32]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func CreateSlate(context *secp256k1.Context, amount uint64, asset string, change uint64, walletInputs []Output) (slateBytes []byte, walletOutput Output, senderSlate SenderSlate, err error) {

	// create a local context object if it's not provided in parameters

	if context == nil {
		context, err = secp256k1.ContextCreate(secp256k1.ContextBoth)
		if err != nil {
			return nil, Output{}, SenderSlate{}, errors.Wrap(err, "ContextCreate failed")
		}
		defer secp256k1.ContextDestroy(context)
	}

	// loop thru wallet inputs to collect slate inputs, sum their values,
	// collect input blinding factors as negative to add them to positive change output's blind

	slateInputs := make([]core.Input, len(walletInputs))
	negativeBlinds := make([][32]byte, len(walletInputs))
	for idx, inp := range walletInputs {
		slateInputs[idx] = core.Input{
			Features: inp.Features,
			Commit: inp.Commit}
		negativeBlinds[idx] = inp.Blind
	}

	// create change output and remember its blinding factor

	var numOutputs int = 0
	if change > 0 {
		numOutputs = 1
	}
	slateOutputs := make([]core.Output, numOutputs)
	positiveBlinds := make([][32]byte, numOutputs)
	if numOutputs == 1 {
		slateOutputs[0], positiveBlinds[0], err = output(context, change, core.PlainOutput)
		if err != nil {
			return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create changeOutput")
		}
	}

	// sum up input and change blinding factors

	sumBlinds, err := secp256k1.BlindSum(context, positiveBlinds, negativeBlinds)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot sum blinding factors")
	}

	// calculate public key for the sum of sender blinding factors

	publicBlindExcessString, err := stringPubKeyFromSecretKey(context, sumBlinds)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	// generate secret nonce and calculate its public key

	nonce, err := secret()
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot get secret for nonce")
	}

	publicNonceString, err := stringPubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create publicNonce")
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
				Inputs:  slateInputs,
				Outputs: slateOutputs,
				Kernels: make([]core.TxKernel, 1),
			},
		},
		Amount:     core.Uint64(amount),
		Fee:        0,
		Height:     0,
		LockHeight: 0,
		ParticipantData: []libwallet.ParticipantData{{
			ID:                0,
			PublicBlindExcess: publicBlindExcessString,
			PublicNonce:       publicNonceString,
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
		}},
	}

	if change > 0 {
		walletOutput = Output{
			Output: slateOutputs[0],
			Blind:  positiveBlinds[0],
			Value:  change,
			Status: OutputUnconfirmed,
			Asset:  asset,
		}
	}

	walletSlate := Slate{
		Slate: *slate,
		Asset: asset,
	}

	slateBytes, err = json.Marshal(walletSlate)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot marshal walletSlate to json")
	}

	senderSlate = SenderSlate{
		Slate:       walletSlate,
		SenderNonce: nonce,
	}
	copy(senderSlate.SumSenderBlinds[:], sumBlinds[:32])
	senderSlate.Status = SlateSent

	return slateBytes, walletOutput, senderSlate, nil
}

func CreateResponse(slateBytes []byte) (responseSlateBytes []byte, walletOutput Output, receiverSlate ReceiverSlate, err error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	var slate = Slate{}

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot unmarshal json to slate")
	}

	// create receiver output and remember its blinding factor

	value := uint64(slate.Amount)

	output, blind, err := output(context, value, core.PlainOutput)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create receiver output")
	}

	// calculate public key for receiver output blinding factor

	res, publicBlindExcess, err := secp256k1.EcPubkeyCreate(context, blind[:])
	if res != 1 || err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	publicBlindExcessString, err := pubKeyToString(context, publicBlindExcess)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicBlindExcessString")
	}

	// choose receiver nonce and calculate its public key

	nonce, err := secret()
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get random for nonce")
	}

	res, publicNonce, err := secp256k1.EcPubkeyCreate(context, nonce[:])
	if res != 1 || err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicNonce")
	}

	publicNonceString, err := pubKeyToString(context, publicNonce)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicNonceString")
	}

	// parse out message to use as part of the Schnorr challenge

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// parse out sender public blind and public nonce

	senderPublicBlindExcess, err := stringToPubKey(context, slate.ParticipantData[0].PublicBlindExcess)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get senderPublicBlindExcess")
	}

	senderPublicNonce, err := stringToPubKey(context, slate.ParticipantData[0].PublicNonce)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get senderPublicNonce")
	}

	// calculate Schnorr challenge

	schnorrChallenge, err := schnorrChallenge(context, msg, senderPublicBlindExcess, senderPublicNonce, publicBlindExcess, publicNonce)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot calculate schnorrChallenge")
	}

	// calculate receiver partial Schnorr signature

	schnorrSig, err := secp256k1.AggsigSignSingle(context, schnorrChallenge, blind[:], nonce[:], nil, nil, nil, nil, dummyseed[:])
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot calculate schnorrSig")
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

	walletOutput = Output{
		Output: output,
		Blind:  blind,
		Value:  value,
		Status: OutputUnconfirmed,
		Asset:  slate.Asset,
	}

	walletSlate := Slate{
		Slate: slate.Slate,
		Asset: slate.Asset,
	}

	slateBytes, err = json.Marshal(walletSlate)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot marshal slate to json")
	}

	receiverSlate = ReceiverSlate{
		Slate:         walletSlate,
		ReceiverNonce: nonce,
	}

	receiverSlate.Status = SlateResponded

	return slateBytes, walletOutput, receiverSlate, nil
}

func CreateTransaction(slateBytes []byte, senderSlate SenderSlate) ([]byte, Transaction, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot ContextCreate")
	}

	defer secp256k1.ContextDestroy(context)

	var slate = Slate{}

	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot unmarshal json to slate")
	}

	sumSenderBlinds := senderSlate.SumSenderBlinds[:]
	senderNonce := senderSlate.SenderNonce[:]

	// parse out message to use as part of the Schnorr challenge

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// parse out public blinds and nonces for both sender and receiver from the slate
	//TODO should the sender trust its public keys in receiver response or use its own, remembered from construction of the slate?

	if len(slate.ParticipantData) != 2 {
		return nil, Transaction{}, errors.New("missing entries in ParticipantData")
	}

	senderPublicBlindExcess, err := stringToPubKey(context, slate.ParticipantData[0].PublicBlindExcess)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get senderPublicBlindExcess")
	}

	senderPublicNonce, err := stringToPubKey(context, slate.ParticipantData[0].PublicNonce)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get senderPublicNonce")
	}

	receiverPublicBlindExcess, err := stringToPubKey(context, slate.ParticipantData[1].PublicBlindExcess)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get receiverPublicBlindExcess")
	}

	receiverPublicNonce, err := stringToPubKey(context, slate.ParticipantData[1].PublicNonce)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get receiverPublicNonce")
	}

	// calculate Schnorr challenge

	schnorrChallenge, err := schnorrChallenge(context, msg, senderPublicBlindExcess, senderPublicNonce, receiverPublicBlindExcess, receiverPublicNonce)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot calculate schnorrChallenge")
	}

	// verify receiver partial signature

	receiverPartialSigBytes, err := hex.DecodeString(*slate.ParticipantData[1].PartSig)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot parse receiverPartialSig from hex")
	}

	if nil != secp256k1.AggsigVerifySingle(context, receiverPartialSigBytes, schnorrChallenge, nil, receiverPublicBlindExcess, nil, nil, false) {
		return nil, Transaction{}, errors.Wrap(err, "cannot verify receiver partial signature")
	}

	// calculate receiver partial Schnorr signature

	senderPartialSigBytes, err := secp256k1.AggsigSignSingle(context, schnorrChallenge, sumSenderBlinds, senderNonce, nil, nil, nil, nil, dummyseed[:])
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot calculate schnorrSig")
	}

	// sum sender and receiver public nonces for the second half of the excess signature

	res, sumPublicNonces, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if res != 1 || err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot sum public nonces")
	}

	// sum sender and receiver partial signatures and append sum of public nonces to form whole two part excess signature

	excessSig, err := secp256k1.AggsigAddSignaturesSingle(context, [][]byte{senderPartialSigBytes, receiverPartialSigBytes}, sumPublicNonces)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot create excess signature")
	}

	excessSigString := hex.EncodeToString(excessSig)

	// calculate kernel excess as a sum of sender and receiver public blinds

	res, excess, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicBlindExcess, receiverPublicBlindExcess})
	if res != 1 || err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot sum public blinds")
	}

	excessString, err := pubKeyToString(context, excess)
	if res != 1 || err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot convert excess to string")
	}

	tx := slate.Transaction

	tx.Body.Kernels[0].Excess = excessString
	tx.Body.Kernels[0].ExcessSig = excessSigString

	ledgerTx := ledger.Transaction{
		Transaction: tx,
		ID:          slate.ID,
	}

	txBytes, err := json.Marshal(ledgerTx)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot marshal identifiedTx to json")
	}

	walletTx := Transaction{
		Transaction: ledgerTx,
		Status:      TransactionUnconfirmed,
		Asset:       slate.Asset,
	}

	return txBytes, walletTx, nil
}

func output(context *secp256k1.Context, value uint64, features core.OutputFeatures) (core.Output, [32]byte, error) {
	blind, err := secret()
	if err != nil {
		return core.Output{}, blind, errors.Wrap(err, "cannot get secret for blind")
	}

	commitment, err := secp256k1.Commit(context, blind[:], value, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return core.Output{}, blind, errors.Wrap(err, "cannot create commitment to value")
	}

	// create bullet proof to value

	// use dummy
	dummynonce := blake256(dummyseed[:])

	proof, err := secp256k1.BulletproofRangeproofProveSingle(context, nil, nil, []uint64{value}, [][]byte{blind[:]}, &secp256k1.GeneratorH, dummynonce[:], nil, nil)
	if err != nil {
		return core.Output{}, blind, errors.Wrapf(err, "cannot create bullet proof")
	}

	output := core.Output{
		Features: features,
		Commit:   commitment.Hex(),
		Proof:    hex.EncodeToString(proof),
	}

	return output, blind, nil
}

func blake256(data []byte) (digest []byte) {

	hash, _ := blake2b.New256(nil)
	hash.Write(data)
	return hash.Sum(nil)
}

func random() ([32]byte, error) {
	s := make([]byte, 32)
	l, err := rand.Read(s)

	var r [32]byte
	copy(r[:], s[:32])

	if l != 32 || err != nil {
		return r, errors.New("cannot generate random")
	}

	return r, nil
}

func secret() ([32]byte, error) {
	return random()
}

func stringPubKeyFromSecretKey(context *secp256k1.Context, sk32 []byte) (string, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(context, sk32)
	if res != 1 || err != nil {
		return "", errors.Wrap(err, "cannot create PublicKey")
	}

	return pubKeyToString(context, pk)
}

func pubKeyToString(context *secp256k1.Context, pk *secp256k1.PublicKey) (string, error) {
	res, pkBytes, err := secp256k1.EcPubkeySerialize(context, pk, uint(compressedPubKeyFlag))
	if res != 1 || err != nil {
		return "", errors.Wrap(err, "cannot serialize PublicKey")
	}

	pkString := hex.EncodeToString(pkBytes)

	return pkString, nil
}

func stringToPubKey(context *secp256k1.Context, s string) (*secp256k1.PublicKey, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode public key from hex string")
	}

	res, pk, err := secp256k1.EcPubkeyParse(context, bytes)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot parse public key from bytes")
	}

	return pk, nil
}

func stringToPubKeyBytes(context *secp256k1.Context, s string) ([]byte, error) {
	pk, err := stringToPubKey(context, s)
	if err != nil {
		return nil, errors.Wrap(err, "cannot convert string to PubKey")
	}

	res, bytes, err := secp256k1.EcPubkeySerialize(context, pk, compressedPubKeyFlag)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot serialize PubKey")
	}

	return bytes, nil
}

func sumPubKeysToBytes(context *secp256k1.Context, pubKeys []*secp256k1.PublicKey) ([]byte, error) {
	res, sumPubKeys, err := secp256k1.EcPubkeyCombine(context, pubKeys)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot sum public keys")
	}

	res, sumPubKeysBytes, err := secp256k1.EcPubkeySerialize(context, sumPubKeys, compressedPubKeyFlag)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot serialize public blinds")
	}

	return sumPubKeysBytes, nil
}

func schnorrChallenge(context *secp256k1.Context, msg []byte, senderPublicBlindExcess *secp256k1.PublicKey, senderPublicNonce *secp256k1.PublicKey, receiverPublicBlindExcess *secp256k1.PublicKey, receiverPublicNonce *secp256k1.PublicKey) ([]byte, error) {
	hash, _ := blake2b.New256(nil)
	hash.Write(msg)

	if senderPublicBlindExcess != nil && senderPublicNonce != nil && receiverPublicBlindExcess != nil && receiverPublicNonce != nil {
		sumPublicBlindsBytes, err := sumPubKeysToBytes(context, []*secp256k1.PublicKey{senderPublicBlindExcess, receiverPublicBlindExcess})
		if err != nil {
			return nil, errors.Wrap(err, "cannot get sumPublicBlindsBytes")
		}

		sumPublicNoncesBytes, err := sumPubKeysToBytes(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
		if err != nil {
			return nil, errors.Wrap(err, "cannot get sumPublicNoncesBytes")
		}

		hash.Write(sumPublicNoncesBytes)
		hash.Write(sumPublicBlindsBytes)
	}

	return hash.Sum(nil), nil
}
