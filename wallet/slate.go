package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

var dummyseed = [32]byte{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func CreateSlate(
	context *secp256k1.Context,
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []Output,
) (
	slateBytes []byte,
	walletOutput Output,
	senderSlate SenderSlate,
	err error,
) {
	// create a local context object if it's not provided in parameters
	if context == nil {
		context, err = secp256k1.ContextCreate(secp256k1.ContextSign)
		if err != nil {
			return nil, Output{}, SenderSlate{}, errors.Wrap(err, "ContextCreate failed")
		}
		defer secp256k1.ContextDestroy(context)
	}

	// loop thru wallet inputs to collect slate inputs, sum their values,
	// collect input blinding factors as negative to add them to positive change output's blind
	var inputsValue uint64
	slateInputs := make([]core.Input, len(walletInputs))
	inputBlinds := make([][32]byte, len(walletInputs))
	for index, input := range walletInputs {
		inputsValue += input.Value
		inputBlinds[index] = input.Blind
		slateInputs[index] = core.Input{
			Features: input.Features,
			Commit:   input.Commit,
		}
	}

	// make sure that amounts provided in input parameters do sum up (inputsValue - amount - fee - change == 0)
	if 0 != - inputsValue + amount + fee + change {
		err = errors.New("Amounts don't sum up (inputsValue - amount - fee - change != 0)")
		return
	}

	// create change output and remember its blinding factor
	var outputBlinds [][32]byte
	var slateOutputs []core.Output
	if change > 0 {
		slateOutputs = make([]core.Output, 1)
		outputBlinds = make([][32]byte, 1)
		slateOutputs[0], outputBlinds[0], err = createOutput(context, change, core.PlainOutput)
		if err != nil {
			return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create changeOutput")
		}
	}

	// sum up input and change blinding factors and calculate its public key
	excess, err := secp256k1.BlindSum(context, outputBlinds, inputBlinds)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot sum blinding factors")
	}
	publicExcess, err := pubKeyFromSecretKey(context, excess)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	// generate secret nonce and calculate its public key
	nonce, err := secret(context)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot get secret for nonce")
	}
	publicNonce, err := pubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create publicNonce")
	}

	// put these all into a slate and marshal it to json

	// TODO calculate transaction offset

	slate := &libwallet.Slate{
		VersionInfo: libwallet.VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 2,
		ID:              uuid.New(),
		Transaction: core.Transaction{
			Offset: "",
			Body: core.TransactionBody{
				Inputs:  slateInputs,
				Outputs: slateOutputs,
				Kernels: []core.TxKernel{{
					Features:   core.PlainKernel,
					Fee: 		core.Uint64(fee),
					LockHeight: 0,
					Excess:     "000000000000000000000000000000000000000000000000000000000000000000",
					ExcessSig:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				}},
			},
		},
		Amount:     core.Uint64(amount),
		Fee:        core.Uint64(fee),
		Height:     0,
		LockHeight: 0,
		ParticipantData: []libwallet.ParticipantData{{
			ID:                0,
			PublicBlindExcess: publicExcess.Hex(context),
			PublicNonce:       publicNonce.Hex(context),
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
		}},
	}

	if change > 0 {
		walletOutput = Output{
			Output: slateOutputs[0],
			Blind:  outputBlinds[0],
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
		Slate: walletSlate}
	copy(senderSlate.SenderNonce[:], nonce[:32])
	copy(senderSlate.SumSenderBlinds[:], excess[:32])
	senderSlate.Status = SlateSent

	return slateBytes, walletOutput, senderSlate, nil
}

/// let secp = Secp256k1::with_caps(ContextFlag::Full);
/// let secret_nonce = aggsig::create_secnonce(&secp).unwrap();
/// let secret_key = SecretKey::new(&secp, &mut thread_rng());
/// let pub_nonce_sum = PublicKey::from_secret_key(&secp, &secret_nonce).unwrap();
/// // ... Add all other participating nonces
/// let pub_key_sum = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
/// // ... Add all other participating keys
/// let mut msg_bytes = [0; 32];
/// // ... Encode message
/// let message = Message::from_slice(&msg_bytes).unwrap();
/// let sig_part = aggsig::calculate_partial_sig(
///		&secp,
///		&secret_key,
///		&secret_nonce,
///		&pub_nonce_sum,
///		Some(&pub_key_sum),
///		&message,
///).unwrap();

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

	value := uint64(slate.Amount)
	//fee := uint64(slate.Fee)

	// create receiver output and remember its blinding factor and calculate its public key
	output, blind, err := createOutput(context, value, core.PlainOutput)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create receiver output")
	}
	publicBlind, err := pubKeyFromSecretKey(context, blind[:])
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	// choose receiver nonce and calculate its public key
	nonce, err := secret(context)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get random for nonce")
	}
	publicNonce, err := pubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicNonce")
	}

	// parse out sender public blind and public nonce
	senderPublicBlind := context.PublicKeyFromHex(slate.ParticipantData[0].PublicBlindExcess)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get senderPublicBlindExcess")
	}
	senderPublicNonce := context.PublicKeyFromHex(slate.ParticipantData[0].PublicNonce)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get senderPublicNonce")
	}

	// Combine public blinds and nonces
	sumPublicBlinds, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicBlind, publicBlind})
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get sumPublicBlindsBytes")
	}
	sumPublicNonces, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicNonce, publicNonce})
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get sumPublicNoncesBytes")
	}

	// parse out message to use as part of the Schnorr challenge
	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// Create receiver's partial signature
	receiverSig, err := secp256k1.AggsigSignSingle(
		context,
		msg[:],
		blind[:],
		nonce[:],
		nil,
		sumPublicNonces,
		sumPublicNonces,
		sumPublicBlinds,
		nil,
	)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot calcuilate receiver's partial signature")
	}

	if nil != secp256k1.AggsigVerifySingle(
		context,
		receiverSig,
		msg,
		sumPublicNonces,
		publicBlind,
		sumPublicBlinds,
		nil,
		true,
	) {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot verify receiver partial signature")
	}

	// // calculate Schnorr challenge

	// schnorrChallenge, err := schnorrChallenge(context, msg,
	//     senderPublicBlindExcess, senderPublicNonce, publicBlindExcess, publicNonce)
	// if err != nil {
	// 	return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot calculate schnorrChallenge")
	// }

	// calculate receiver partial Schnorr signature

	// schnorrSig, err := secp256k1.AggsigSignSingle(
	// 	context,
	// 	msg, blind[:], nonce[:], nil, nil, nil, nil, dummyseed[:])
	// if err != nil {
	// 	return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot calculate schnorrSig")
	// }
	receiverSigString := hex.EncodeToString(receiverSig)

	slate.ParticipantData = append(slate.ParticipantData, libwallet.ParticipantData{
		ID:                1,
		PublicBlindExcess: publicBlind.Hex(context),
		PublicNonce:       publicNonce.Hex(context),
		PartSig:           &receiverSigString,
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

func calculatePartialSig(
	context *secp256k1.Context,
	sec_key []byte,
	sec_nonce []byte,
	nonce_sum *secp256k1.PublicKey,
	pubkey_sum *secp256k1.PublicKey,
	msg []byte,
) (
	sig []byte,
	err error,
) {
	//Now calculate signature using message M=fee, nonce in e=nonce_sum
	sig, err = secp256k1.AggsigSignSingle(
		context,
		msg,
		sec_key,
		sec_nonce,
		nil,
		nonce_sum,
		nonce_sum,
		pubkey_sum,
		nil,
	)
	return
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

	senderBlind := senderSlate.SumSenderBlinds[:]
	senderNonce := senderSlate.SenderNonce[:]

	// parse out message to use as part of the Schnorr challenge

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// parse out public blinds and nonces for both sender and receiver from the slate

	if len(slate.ParticipantData) != 2 {
		return nil, Transaction{}, errors.New("missing entries in ParticipantData")
	}

	// get public keys from slate
	senderPublicBlind := context.PublicKeyFromHex(slate.ParticipantData[0].PublicBlindExcess)
	senderPublicNonce := context.PublicKeyFromHex(slate.ParticipantData[0].PublicNonce)

	// calculate public keys from secret keys
	senderPublicBlind_, _ := pubKeyFromSecretKey(context, senderBlind)
	senderPublicNonce_, _ := pubKeyFromSecretKey(context, senderNonce)

	// should the sender trust its public keys in receiver response or use its own, remembered from construction of the slate?
	if (0 != bytes.Compare(senderPublicBlind.Bytes(context), senderPublicBlind_.Bytes(context))) ||
	   (0 != bytes.Compare(senderPublicNonce.Bytes(context), senderPublicNonce_.Bytes(context))) {
		return nil, Transaction{}, errors.Wrap(err, "public keys mismatch, calculated values are not the same as loaded from slate")
	}

	receiverPublicBlind := context.PublicKeyFromHex(slate.ParticipantData[1].PublicBlindExcess)
	receiverPublicNonce := context.PublicKeyFromHex(slate.ParticipantData[1].PublicNonce)

	// // calculate Schnorr challengeKernelSignatureMessage(slate.Transaction.Body.Kernels[0])
	// schnorrChallenge, err := schnorrChallenge(context, msg, senderPublicBlindExcess, senderPublicNonce, receiverPublicBlindExcess, receiverPublicNonce)
	// if err != nil {
	// 	return nil, Transaction{}, errors.Wrap(err, "cannot calculate schnorrChallenge")
	// }
	sumPublicBlinds, err := sumPubKeys(context,
		[]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get sumPublicBlindsBytes")
	}

	sumPublicNonces, err := sumPubKeys(context,
		[]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get sumPublicNoncesBytes")
	}

	// verify receiver partial signature

	receiverPartialSigBytes, err := hex.DecodeString(*slate.ParticipantData[1].PartSig)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot parse receiverPartialSig from hex")
	}

	if nil != secp256k1.AggsigVerifySingle(
		context,
		receiverPartialSigBytes,
		msg,
		sumPublicNonces,
		receiverPublicBlind,
		sumPublicBlinds,
		nil,
		true,
	) {
		return nil, Transaction{}, errors.Wrap(err, "cannot verify receiver partial signature")
	}

	// calculate receiver partial Schnorr signature

	senderPartialSigBytes, err := calculatePartialSig(
		context,
		senderBlind, senderNonce,
		sumPublicNonces, sumPublicBlinds,
		msg,
	)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot calculate schnorrSig")
	}

	// // sum sender and receiver public nonces for the second half of the excess signature

	// res, sumPublicNonces, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	// if res != 1 || err != nil {
	// 	return nil, Transaction{}, errors.Wrap(err, "cannot sum public nonces")
	// }

	// sum sender and receiver partial signatures and append sum of public nonces to form whole two part excess signature

	excessSig, err := secp256k1.AggsigAddSignaturesSingle(context, [][]byte{senderPartialSigBytes, receiverPartialSigBytes}, sumPublicNonces)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot create excess signature")
	}

	excessSigString := hex.EncodeToString(excessSig)

	// // calculate kernel excess as a sum of sender and receiver public blinds

	// res, excess, err := secp256k1.EcPubkeyCombine(context, []*secp256k1.PublicKey{senderPublicBlindExcess, receiverPublicBlindExcess})
	// if res != 1 || err != nil {
	// 	return nil, Transaction{}, errors.Wrap(err, "cannot sum public blinds")
	// }

	excessString := sumPublicBlinds.Hex(context) // excess)

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

func createOutput(
	context *secp256k1.Context,
	value uint64,
	features core.OutputFeatures,
) (
	output core.Output,
	bytes [32]byte,
	err error,
) {
	blind, err := secret(context)
	if err != nil {
		return core.Output{}, blind, errors.Wrap(err, "cannot get secret for blind")
	}

	commitment, err := secp256k1.Commit(context, blind[:], value, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	if err != nil {
		return core.Output{}, blind, errors.Wrap(err, "cannot create commitment to value")
	}

	// create bullet proof to value

	rnd := secp256k1.Random256()
	proof, err := secp256k1.BulletproofRangeproofProveSingle(
		context, nil, nil,
		[]uint64{value}, [][]byte{blind[:]},
		&secp256k1.GeneratorH, rnd[:], nil, nil)
	if err != nil {
		return core.Output{}, blind, errors.Wrapf(err, "cannot create bullet proof")
	}

	output = core.Output{
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

func secret(context *secp256k1.Context) (rnd32 [32]byte, err error) {
	seed32 := secp256k1.Random256()
	rnd32, err = secp256k1.AggsigGenerateSecureNonce(context, seed32[:])
	return
}

func pubKeyFromSecretKey(context *secp256k1.Context, sk32 []byte) (*secp256k1.PublicKey, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(context, sk32)
	if res != 1 || pk == nil || err != nil {
		return nil, errors.Wrap(err, "cannot create Public key from Secret key")
	}

	return pk, nil
}

/*func stringPubKeyFromSecretKey(context *secp256k1.Context, sk32 []byte) (pubkeystr string, pubkey *secp256k1.PublicKey, err error) {
	pubkey, err = pubKeyFromSecretKey(context, sk32)
	if err != nil {
		return "", nil, errors.Wrap(err, "cannot create PublicKey")
	}

	pubkeystr, err = pubKeyToString(context, pubkey)
	return
}

func pubKeyToString(context *secp256k1.Context, pk *secp256k1.PublicKey) (string, error) {
	res, pkBytes, err := secp256k1.EcPubkeySerialize(context, pk, uint(secp256k1.EcCompressed))
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

	res, bytes, err := secp256k1.EcPubkeySerialize(context, pk, secp256k1.EcCompressed)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot serialize PubKey")
	}

	return bytes, nil
}*/

func sumPubKeys(
	context *secp256k1.Context,
	pubkeys []*secp256k1.PublicKey,
) (
	sum *secp256k1.PublicKey,
	err error,
) {
	res, sum, err := secp256k1.EcPubkeyCombine(context, pubkeys)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot sum public keys")
	}

	return
}
//
// func schnorrChallenge(context *secp256k1.Context, msg []byte, senderPublicBlindExcess *secp256k1.PublicKey, senderPublicNonce *secp256k1.PublicKey, receiverPublicBlindExcess *secp256k1.PublicKey, receiverPublicNonce *secp256k1.PublicKey) ([]byte, error) {
// 	hash, _ := blake2b.New256(nil)
// 	hash.Write(msg)
//
// 	if senderPublicBlindExcess != nil && senderPublicNonce != nil && receiverPublicBlindExcess != nil && receiverPublicNonce != nil {
// 		sumPublicBlindsBytes, _, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicBlindExcess, receiverPublicBlindExcess})
// 		if err != nil {
// 			return nil, errors.Wrap(err, "cannot get sumPublicBlindsBytes")
// 		}
//
// 		sumPublicNoncesBytes, _, err := sumPubKeysToBytes(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
// 		if err != nil {
// 			return nil, errors.Wrap(err, "cannot get sumPublicNoncesBytes")
// 		}
//
// 		hash.Write(sumPublicNoncesBytes)
// 		hash.Write(sumPublicBlindsBytes)
// 	}
//
// 	return hash.Sum(nil), nil
// }
//