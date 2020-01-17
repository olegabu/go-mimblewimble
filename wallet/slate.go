package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
)

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
		if context, err = secp256k1.ContextCreate(secp256k1.ContextBoth); err != nil {
			return nil, Output{}, SenderSlate{}, errors.Wrap(err, "ContextCreate failed")
		}
		defer secp256k1.ContextDestroy(context)
	}

	// loop thru wallet inputs to collect slate inputs, sum their values,
	// collect input blinding factors (negative)
	var inputsTotal uint64
	var inputBlinds [][]byte
	var slateInputs []core.Input
	for _, input := range walletInputs {
		inputsTotal += input.Value
		var blind [32]byte
		copy(blind[:], input.Blind[:])
		inputBlinds = append(inputBlinds, blind[:])
		slateInputs = append(slateInputs, core.Input{
			Features: input.Features,
			Commit:   input.Commit,
		})
	}

	// make sure that amounts provided in input parameters do sum up (inputsValue - amount - fee - change == 0)
	if 0 != -inputsTotal+amount+fee+change {
		err = errors.New("Amounts don't sum up (inputsValue - amount - fee - change != 0)")
		return
	}

	// create and remember blinding factor for change output
	var outputBlinds [][]byte
	var slateOutputs []core.Output
	var changeOutput *Output
	if change > 0 {
		_, changeOutput, err = createOutput(context, nil, change, core.PlainOutput, asset, OutputUnconfirmed)
		if err != nil {
			return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create changeOutput")
		}
		var blind [32]byte
		copy(blind[:], changeOutput.Blind[:])
		outputBlinds = append(outputBlinds, blind[:])
		slateOutputs = append(slateOutputs, changeOutput.Output)
	}
	// sum up inputs(-) and outputs(+) blinding factors and calculate sum's public key
	blindExcess1, err := secp256k1.BlindSum(context, outputBlinds, inputBlinds)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create blinding excess sum")
	}

	// generate secret nonce and calculate its public key
	nonce, err := secret(context)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot get secret for nonce")
	}

	// generate random kernel offset
	kernelOffset, err := secret(context)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot get random offset")
	}

	// Subtract kernel offset from blinding excess sum
	blindExcess, err := secp256k1.BlindSum(context, [][]byte{blindExcess1[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot get offset for blind")
	}

	publicBlindExcess, err := pubKeyFromSecretKey(context, blindExcess[:])
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	// Create public curve points from blindExcess
	publicNonce, err := pubKeyFromSecretKey(context, nonce[:])
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot create publicNonce")
	}

	// put these all into a slate and marshal it to json

	slate := &libwallet.Slate{
		VersionInfo: libwallet.VersionCompatInfo{
			Version:            3,
			OrigVersion:        3,
			BlockHeaderVersion: 2,
		},
		NumParticipants: 2,
		ID:              uuid.New(),
		Transaction: core.Transaction{
			Offset: hex.EncodeToString(kernelOffset[:]),
			Body: core.TransactionBody{
				Inputs:  slateInputs,
				Outputs: slateOutputs,
				Kernels: []core.TxKernel{{
					Features:   core.PlainKernel,
					Fee:        core.Uint64(fee),
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
			PublicBlindExcess: publicBlindExcess.Hex(context),
			PublicNonce:       publicNonce.Hex(context),
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
		}},
	}

	walletSlate := Slate{
		Slate: *slate,
		Asset: asset,
	}

	slateBytes, err = json.Marshal(walletSlate)
	if err != nil {
		return nil, Output{}, SenderSlate{}, errors.Wrap(err, "cannot marshal walletSlate to json")
	}

	senderSlate = SenderSlate{Slate: walletSlate}
	copy(senderSlate.SenderNonce[:], nonce[:])
	copy(senderSlate.SumSenderBlinds[:], blindExcess[:])
	senderSlate.Status = SlateSent

	return slateBytes, *changeOutput, senderSlate, nil
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

func CreateResponse(
	slateBytes []byte,
) (
	responseSlateBytes []byte,
	walletOutput Output,
	receiverSlate ReceiverSlate,
	err error,
) {

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
	// fee := uint64(slate.Fee)

	// create receiver output and remember its blinding factor and calculate its public key
	output, outerOutput, err := createOutput(context, nil, value, core.PlainOutput, slate.Asset, OutputUnconfirmed)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create receiver output")
	}
	receiverPublicBlind, err := pubKeyFromSecretKey(context, outerOutput.Blind[:])
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicBlindExcess")
	}

	// choose receiver nonce and calculate its public key
	receiverNonce, err := secret(context)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get random for nonce")
	}
	receiverPublicNonce, err := pubKeyFromSecretKey(context, receiverNonce[:])
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot create publicNonce")
	}

	// parse out sender public blind and public nonce
	senderPublicBlind := context.PublicKeyFromHex(slate.ParticipantData[0].PublicBlindExcess)
	if senderPublicBlind == nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get senderPublicBlindExcess")
	}
	senderPublicNonce := context.PublicKeyFromHex(slate.ParticipantData[0].PublicNonce)
	if senderPublicNonce == nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get senderPublicNonce")
	}

	// Combine public blinds and nonces
	sumPublicBlinds, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get sumPublicBlindsBytes")
	}
	sumPublicNonces, err := sumPubKeys(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot get sumPublicNoncesBytes")
	}

	// Calculate message digest for the kernel signature
	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// Create Receiver's partial signature
	receiverPartSig, err := secp256k1.AggsigSignPartial(
		context,
		outerOutput.Blind[:], receiverNonce[:],
		sumPublicNonces, sumPublicBlinds,
		msg,
	)
	if err != nil {
		return nil, Output{}, ReceiverSlate{}, errors.Wrap(err, "cannot calcuilate receiver's partial signature")
	}

	// Add transaction output
	slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, *output)

	// Update slate with the receiver's info
	receiverPartSigBytes := secp256k1.AggsigSignaturePartialSerialize(&receiverPartSig)
	receiverPartSigString := hex.EncodeToString(receiverPartSigBytes[:])
	slate.ParticipantData = append(slate.ParticipantData, libwallet.ParticipantData{
		ID:                1,
		PublicBlindExcess: receiverPublicBlind.Hex(context),
		PublicNonce:       receiverPublicNonce.Hex(context),
		PartSig:           &receiverPartSigString,
		Message:           nil,
		MessageSig:        nil,
	})

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
		ReceiverNonce: receiverNonce,
	}
	receiverSlate.Status = SlateResponded

	return slateBytes, *outerOutput, receiverSlate, nil
}

func CreateTransaction(slateBytes []byte, senderSlate SenderSlate) ([]byte, Transaction, error) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot ContextCreate")
	}
	defer secp256k1.ContextDestroy(context)

	// get secret keys from sender's slate that has blind and nonce secrets
	senderBlind := senderSlate.SumSenderBlinds[:]
	senderNonce := senderSlate.SenderNonce[:]
	// calculate public keys from secret keys
	senderPublicBlind_, _ := pubKeyFromSecretKey(context, senderBlind)
	senderPublicNonce_, _ := pubKeyFromSecretKey(context, senderNonce)

	// parse slate

	var slate = Slate{}
	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot unmarshal json to slate")
	}

	// parse out public blinds and nonces for both sender and receiver from the slate

	if len(slate.ParticipantData) != 2 {
		return nil, Transaction{}, errors.New("missing entries in ParticipantData")
	}

	// Get public keys from slate
	senderPublicBlind := context.PublicKeyFromHex(slate.ParticipantData[0].PublicBlindExcess)
	senderPublicNonce := context.PublicKeyFromHex(slate.ParticipantData[0].PublicNonce)

	// Verify that the response we've got from Receiver has Sender's public key and nonce unchanghed
	if (0 != bytes.Compare(senderPublicBlind.Bytes(context), senderPublicBlind_.Bytes(context))) ||
		(0 != bytes.Compare(senderPublicNonce.Bytes(context), senderPublicNonce_.Bytes(context))) {
		return nil, Transaction{}, errors.Wrap(err, "public keys mismatch, calculated values are not the same as loaded from slate")
	}

	receiverPublicBlind := context.PublicKeyFromHex(slate.ParticipantData[1].PublicBlindExcess)
	receiverPublicNonce := context.PublicKeyFromHex(slate.ParticipantData[1].PublicNonce)

	var sumPublicBlinds, sumPublicNonces *secp256k1.PublicKey
	if sumPublicBlinds, err = sumPubKeys(context, []*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind}); err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get sumPublicBlindsBytes")
	}
	if sumPublicNonces, err = sumPubKeys(context, []*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce}); err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot get sumPublicNoncesBytes")
	}

	// calculate message hash
	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// decode receiver's partial signature
	receiverPartSigBytes, err := hex.DecodeString(*slate.ParticipantData[1].PartSig)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot parse receiverPartialSig from hex")
	}
	receiverPartSig, err := secp256k1.AggsigSignaturePartialParse(receiverPartSigBytes)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot parse receiverPartialSig from hex")
	}

	// Verify receiver's partial signature

	if nil != secp256k1.AggsigVerifyPartial(
		context,
		&receiverPartSig,
		sumPublicNonces,
		receiverPublicBlind,
		sumPublicBlinds,
		msg,
	) {
		return nil, Transaction{}, errors.Wrap(err, "cannot verify receiver partial signature")
	}

	// Calculate sender's partial signature

	senderPartSig, err := secp256k1.AggsigSignPartial(
		context,
		senderBlind,
		senderNonce,
		sumPublicNonces,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot calculate sender partial signature")
	}

	// verify sender's partial signature

	if nil != secp256k1.AggsigVerifyPartial(
		context,
		&senderPartSig,
		sumPublicNonces,
		senderPublicBlind,
		sumPublicBlinds,
		msg,
	) {
		return nil, Transaction{}, errors.Wrap(err, "cannot verify sender partial signature")
	}

	// Finalize the transaction

	finalSig, err := secp256k1.AggsigAddSignaturesSingle(
		context,
		[]*secp256k1.AggsigSignaturePartial{
			&senderPartSig,
			&receiverPartSig,
		},
		sumPublicNonces)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot create excess signature")
	}

	// Verify final sig

	err = secp256k1.AggsigVerifySingle(
		context,
		&finalSig,
		msg,
		nil,
		sumPublicBlinds,
		sumPublicBlinds,
		nil,
		false,
	)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot verify excess signature")
	}

	tx := slate.Transaction

	// calculate kernel excess as a sum of commitments of inputs, outputs and kernel offset
	// that would produce a *Commitment type result
	kernelExcess, err := ledger.CalculateExcess(context, &tx, uint64(slate.Fee))
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "cannot calculate final kernel excess")
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(context, kernelExcess)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "excessPublicKey: CommitmentToPublicKey failed")
	}

	kernelExcess2 := sumPublicBlinds.Bytes(context)
	kernelExcess2[0] += 6

	// Verify final sig with pk from excess

	err = secp256k1.AggsigVerifySingle(
		context,
		&finalSig,
		msg,
		sumPublicNonces,
		excessPublicKey,
		excessPublicKey,
		nil,
		false)
	if err != nil {
		return nil, Transaction{}, errors.Wrap(err, "AggsigVerifySingle failed to verify the finalSig with excessPublicKey")
	}

	excessSig := secp256k1.AggsigSignatureSerialize(context, &finalSig)

	tx.Body.Kernels[0].Excess = kernelExcess.Hex(context)
	tx.Body.Kernels[0].ExcessSig = hex.EncodeToString(excessSig[:])

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
	blind []byte,
	value uint64,
	features core.OutputFeatures,
	asset string,
	status OutputStatus,
) (
	output *core.Output,
	outputOuter *Output,
	err error,
) {
	if blind == nil {
		blind_, err_ := secret(context)
		if err_ != nil {
			return nil, nil, err_
		}
		blind = blind_[:]
	}

	// create commitment to value and blinding factor
	commitment, err := secp256k1.Commit(
		context,
		blind,
		value,
		&secp256k1.GeneratorH,
		&secp256k1.GeneratorG)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create commitment to value")
	}

	// create bullet proof to value
	proof, err := secp256k1.BulletproofRangeproofProveSingle(
		context,
		nil,
		nil,
		value,
		blind,
		blind,
		nil,
		nil,
		nil)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot create bullet proof")
	}

	output = &core.Output{
		Features: features,
		Commit:   commitment.Hex(context),
		Proof:    hex.EncodeToString(proof),
	}

	outputOuter = &Output{
		Output: *output,
		Value:  value,
		Asset:  asset,
		Status: status,
	}
	copy(outputOuter.Blind[:], blind)

	return output, outputOuter, nil
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
