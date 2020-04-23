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
)

func (t *Wallet) CreateSlate(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []Output,
) (
	walletSlateBytes []byte,
	changeOutput *Output,
	senderSlate SenderSlate,
	err error,
) {
	// loop thru wallet inputs to turn them into slate inputs, sum their values,
	// collect input blinding factors (negative)
	var inputsTotal uint64
	var inputBlinds [][]byte
	var slateInputs []core.Input
	for _, input := range walletInputs {
		inputsTotal += input.Value
		// re-create child secret key from its saved index and use it as this input's blind
		secret, e := t.secret(input.Index)
		if e != nil {
			err = errors.Wrapf(e, "cannot get secret for input with key index %d", input.Index)
			return
		}
		inputBlinds = append(inputBlinds, secret[:])
		slateInputs = append(slateInputs, core.Input{Features: input.Features, Commit: input.Commit})
	}

	// make sure that amounts provided in input parameters do sum up (inputsValue - amount - fee - change == 0)
	if amount+change+fee != inputsTotal {
		err = errors.New("amounts don't sum up (amount + change + fee != inputsTotal)")
		return
	}

	// create change output and remember its blinding factor
	var outputBlinds [][]byte
	var slateOutputs []core.Output
	if change > 0 {
		o, b, e := t.createOutput(change, core.PlainOutput, asset, OutputUnconfirmed)
		if e != nil {
			err = errors.Wrap(e, "cannot create changeOutput")
			return
		}
		outputBlinds = append(outputBlinds, b)
		slateOutputs = append(slateOutputs, o.Output)
		changeOutput = o
	}

	// sum up inputs(-) and outputs(+) blinding factors and calculate their sum's public key
	blindExcess, err := secp256k1.BlindSum(t.context, outputBlinds, inputBlinds)
	if err != nil {
		err = errors.Wrap(err, "cannot create blinding excess sum")
		return
	}

	// generate secret nonce
	nonce, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	// generate random kernel offset
	kernelOffset, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get random offset")
		return
	}

	// subtract kernel offset from blinding excess
	sumSenderBlinds, err := secp256k1.BlindSum(t.context, [][]byte{blindExcess[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		err = errors.Wrap(err, "cannot get offset for blind")
		return
	}

	publicBlindExcess, err := t.pubKeyFromSecretKey(sumSenderBlinds[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlindExcess")
		return
	}

	publicNonce, err := t.pubKeyFromSecretKey(nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
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
			PublicBlindExcess: publicBlindExcess.Hex(t.context),
			PublicNonce:       publicNonce.Hex(t.context),
			PartSig:           nil,
			Message:           nil,
			MessageSig:        nil,
		}},
	}

	walletSlate := Slate{
		Slate:  *slate,
		Asset:  asset,
		Status: SlateSent,
	}

	walletSlateBytes, err = json.Marshal(walletSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal walletSlate to json")
		return
	}

	senderSlate = SenderSlate{
		Slate:           walletSlate,
		SenderNonce:     nonce,
		SumSenderBlinds: sumSenderBlinds,
	}

	return
}

func (t *Wallet) CreateResponse(
	slateBytes []byte,
) (
	walletSlateBytes []byte,
	walletOutput *Output,
	receiverSlate ReceiverSlate,
	err error,
) {
	var slate = Slate{}
	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal json to slate")
		return
	}

	value := uint64(slate.Amount)
	// fee := uint64(slate.Fee)

	// create receiver output and remember its blinding factor and calculate its public key
	walletOutput, outputBlind, err := t.createOutput(value, core.PlainOutput, slate.Asset, OutputUnconfirmed)
	if err != nil {
		err = errors.Wrap(err, "cannot create receiver output")
		return
	}
	receiverPublicBlind, err := t.pubKeyFromSecretKey(outputBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlindExcess")
		return
	}

	// choose receiver nonce and calculate its public key
	receiverNonce, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}
	receiverPublicNonce, err := t.pubKeyFromSecretKey(receiverNonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
	}

	// parse out sender public blind and public secret
	senderPublicBlind := t.context.PublicKeyFromHex(slate.ParticipantData[0].PublicBlindExcess)
	if senderPublicBlind == nil {
		err = errors.Wrap(err, "cannot get senderPublicBlindExcess")
		return
	}
	senderPublicNonce := t.context.PublicKeyFromHex(slate.ParticipantData[0].PublicNonce)
	if senderPublicNonce == nil {
		err = errors.Wrap(err, "cannot get senderPublicNonce")
		return
	}

	// Combine public blinds and nonces
	sumPublicBlinds, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicBlindsBytes")
		return
	}
	sumPublicNonces, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicNoncesBytes")
		return
	}

	// Calculate message digest for the kernel signature
	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// Create Receiver's partial signature
	receiverPartSig, err := secp256k1.AggsigSignPartial(
		t.context,
		outputBlind, receiverNonce[:],
		sumPublicNonces, sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate receiver's partial signature")
		return
	}

	// Add transaction output
	slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, walletOutput.Output)

	// Update slate with the receiver's info
	receiverPartSigBytes := secp256k1.AggsigSignaturePartialSerialize(&receiverPartSig)
	receiverPartSigString := hex.EncodeToString(receiverPartSigBytes[:])
	slate.ParticipantData = append(slate.ParticipantData, libwallet.ParticipantData{
		ID:                1,
		PublicBlindExcess: receiverPublicBlind.Hex(t.context),
		PublicNonce:       receiverPublicNonce.Hex(t.context),
		PartSig:           &receiverPartSigString,
		Message:           nil,
		MessageSig:        nil,
	})

	walletSlate := Slate{
		Slate:  slate.Slate,
		Asset:  slate.Asset,
		Status: SlateResponded,
	}

	walletSlateBytes, err = json.Marshal(walletSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	receiverSlate = ReceiverSlate{
		Slate:         walletSlate,
		ReceiverNonce: receiverNonce,
	}

	return
}

func (t *Wallet) CreateTransaction(slateBytes []byte, senderSlate SenderSlate) (ledgerTxBytes []byte, walletTx Transaction, err error) {
	// get secret keys from sender's slate that has blind and secret nonces
	senderBlind := senderSlate.SumSenderBlinds[:]
	senderNonce := senderSlate.SenderNonce[:]
	// calculate public keys from secret keys
	senderPublicBlind_, _ := t.pubKeyFromSecretKey(senderBlind)
	senderPublicNonce_, _ := t.pubKeyFromSecretKey(senderNonce)

	// parse slate

	var slate = Slate{}
	err = json.Unmarshal(slateBytes, &slate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal json to slate")
		return
	}

	// parse out public blinds and nonces for both sender and receiver from the slate

	if len(slate.ParticipantData) != 2 {
		err = errors.New("expected 2 entries in ParticipantData")
		return
	}

	// Get public keys from slate
	senderPublicBlind := t.context.PublicKeyFromHex(slate.ParticipantData[0].PublicBlindExcess)
	senderPublicNonce := t.context.PublicKeyFromHex(slate.ParticipantData[0].PublicNonce)

	// Verify that the response we've got from Receiver has Sender's public key and secret unchanghed
	if (0 != bytes.Compare(senderPublicBlind.Bytes(t.context), senderPublicBlind_.Bytes(t.context))) ||
		(0 != bytes.Compare(senderPublicNonce.Bytes(t.context), senderPublicNonce_.Bytes(t.context))) {
		err = errors.Wrap(err, "public keys mismatch, calculated values are not the same as loaded from slate")
		return
	}

	receiverPublicBlind := t.context.PublicKeyFromHex(slate.ParticipantData[1].PublicBlindExcess)
	receiverPublicNonce := t.context.PublicKeyFromHex(slate.ParticipantData[1].PublicNonce)

	var sumPublicBlinds, sumPublicNonces *secp256k1.PublicKey
	if sumPublicBlinds, err = t.sumPubKeys([]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind}); err != nil {
		err = errors.Wrap(err, "cannot get sumPublicBlindsBytes")
		return
	}
	if sumPublicNonces, err = t.sumPubKeys([]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce}); err != nil {
		err = errors.Wrap(err, "cannot get sumPublicNoncesBytes")
		return
	}

	// calculate message hash
	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	// decode receiver's partial signature
	receiverPartSigBytes, err := hex.DecodeString(*slate.ParticipantData[1].PartSig)
	if err != nil {
		err = errors.Wrap(err, "cannot parse receiverPartialSig from hex")
		return
	}
	receiverPartSig, err := secp256k1.AggsigSignaturePartialParse(receiverPartSigBytes)
	if err != nil {
		err = errors.Wrap(err, "cannot parse receiverPartialSig from hex")
		return
	}

	// Verify receiver's partial signature

	if nil != secp256k1.AggsigVerifyPartial(
		t.context,
		&receiverPartSig,
		sumPublicNonces,
		receiverPublicBlind,
		sumPublicBlinds,
		msg,
	) {
		err = errors.Wrap(err, "cannot verify receiver partial signature")
		return
	}

	// Calculate sender's partial signature

	senderPartSig, err := secp256k1.AggsigSignPartial(
		t.context,
		senderBlind,
		senderNonce,
		sumPublicNonces,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate sender partial signature")
		return
	}

	// verify sender's partial signature

	if nil != secp256k1.AggsigVerifyPartial(
		t.context,
		&senderPartSig,
		sumPublicNonces,
		senderPublicBlind,
		sumPublicBlinds,
		msg,
	) {
		err = errors.Wrap(err, "cannot verify sender partial signature")
		return
	}

	// Finalize the transaction

	finalSig, err := secp256k1.AggsigAddSignaturesSingle(
		t.context,
		[]*secp256k1.AggsigSignaturePartial{
			&senderPartSig,
			&receiverPartSig,
		},
		sumPublicNonces)
	if err != nil {
		err = errors.Wrap(err, "cannot create excess signature")
		return
	}

	// Verify final sig

	err = secp256k1.AggsigVerifySingle(
		t.context,
		&finalSig,
		msg,
		nil,
		sumPublicBlinds,
		sumPublicBlinds,
		nil,
		false,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify excess signature")
		return
	}

	tx := slate.Transaction

	// calculate kernel excess as a sum of commitments of inputs, outputs and kernel offset
	// that would produce a *Commitment type result
	kernelExcess, err := ledger.CalculateExcess(t.context, &tx, uint64(slate.Fee))
	if err != nil {
		err = errors.Wrap(err, "cannot calculate final kernel excess")
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(t.context, kernelExcess)
	if err != nil {
		err = errors.Wrap(err, "excessPublicKey: CommitmentToPublicKey failed")
		return
	}

	// Verify final sig with pk from excess

	err = secp256k1.AggsigVerifySingle(
		t.context,
		&finalSig,
		msg,
		sumPublicNonces,
		excessPublicKey,
		excessPublicKey,
		nil,
		false)
	if err != nil {
		err = errors.Wrap(err, "AggsigVerifySingle failed to verify the finalSig with excessPublicKey")
		return
	}

	excessSig := secp256k1.AggsigSignatureSerialize(t.context, &finalSig)

	tx.Body.Kernels[0].Excess = kernelExcess.String()

	tx.Body.Kernels[0].ExcessSig = hex.EncodeToString(excessSig[:])

	ledgerTx := ledger.Transaction{
		Transaction: tx,
		ID:          slate.ID,
	}

	ledgerTxBytes, err = json.Marshal(ledgerTx)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal ledgerTx to json")
		return
	}

	walletTx = Transaction{
		Transaction: ledgerTx,
		Status:      TransactionUnconfirmed,
		Asset:       slate.Asset,
	}

	return
}

func (t *Wallet) createOutput(
	value uint64,
	features core.OutputFeatures,
	asset string,
	status OutputStatus,
) (
	walletOutput *Output,
	blind []byte,
	err error,
) {
	secret, index, err := t.newSecret()
	if err != nil {
		err = errors.Wrap(err, "cannot get newSecret")
		return
	}

	blind = secret[:]

	// create commitment to value and blinding factor
	commitment, err := secp256k1.Commit(
		t.context,
		blind,
		value,
		&secp256k1.GeneratorH,
		&secp256k1.GeneratorG)
	if err != nil {
		err = errors.Wrap(err, "cannot create commitment to value")
		return
	}

	// create bullet proof to value
	proof, err := secp256k1.BulletproofRangeproofProveSingle(
		t.context,
		nil,
		nil,
		value,
		blind[:],
		blind[:],
		nil,
		nil,
		nil)
	if err != nil {
		err = errors.Wrap(err, "cannot create bullet proof")
		return
	}

	walletOutput = &Output{
		Output: core.Output{
			Features: features,
			Commit:   commitment.String(),
			Proof:    hex.EncodeToString(proof),
		},
		Value:  value,
		Asset:  asset,
		Index:  index,
		Status: status,
	}

	return
}

func (t *Wallet) pubKeyFromSecretKey(sk32 []byte) (*secp256k1.PublicKey, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(t.context, sk32)
	if res != 1 || pk == nil || err != nil {
		return nil, errors.Wrap(err, "cannot create Public key from Secret key")
	}

	return pk, nil
}

func (t *Wallet) sumPubKeys(
	pubkeys []*secp256k1.PublicKey,
) (
	sum *secp256k1.PublicKey,
	err error,
) {
	res, sum, err := secp256k1.EcPubkeyCombine(t.context, pubkeys)
	if res != 1 || err != nil {
		return nil, errors.Wrap(err, "cannot sum public keys")
	}

	return
}
