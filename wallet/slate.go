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

func (t *Wallet) NewSend(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []Output,
) (
	slateBytes []byte,
	changeOutput *Output,
	savedSlate *SavedSlate,
	err error,
) {
	slateInputs, changeOutput, blindExcess, err := t.slateInputsAndChange(
		amount,
		fee,
		asset,
		change,
		walletInputs)
	if err != nil {
		err = errors.Wrap(err, "cannot create slate inputs and outputs")
		return
	}

	var slateOutputs []core.Output
	if changeOutput != nil {
		slateOutputs = append(slateOutputs, changeOutput.Output)
	}

	slateBytes, savedSlate, err = t.newSlate(slateInputs, slateOutputs, amount, fee, asset, blindExcess[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create newSlate")
		return
	}

	return
}

func (t *Wallet) slateInputsAndChange(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []Output,
) (
	slateInputs []core.Input,
	changeOutput *Output,
	blindExcess [32]byte,
	err error,
) {
	// loop thru wallet inputs to turn them into slate inputs, sum their values,
	// collect input blinding factors (negative)
	var inputsTotal uint64
	var inputBlinds [][]byte
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
	if change > 0 {
		o, b, e := t.newOutput(change, core.PlainOutput, asset, OutputUnconfirmed)
		if e != nil {
			err = errors.Wrap(e, "cannot create change output")
			return
		}
		outputBlinds = append(outputBlinds, b)
		changeOutput = o
	}

	// sum up inputs(-) and outputs(+) blinding factors
	blindExcess, err = secp256k1.BlindSum(t.context, outputBlinds, inputBlinds)
	if err != nil {
		err = errors.Wrap(err, "cannot create blinding excess sum")
		return
	}

	return
}

func (t *Wallet) respond(slate *Slate, output core.Output, outputBlind []byte) (receiverNonce [32]byte, err error) {
	// add responder output (receiver's in Send, payer's change in Invoice)
	slate.Transaction.Body.Outputs = append(slate.Transaction.Body.Outputs, output)

	receiverPublicBlind, err := t.pubKeyFromSecretKey(outputBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlind")
		return
	}

	// choose receiver nonce and calculate its public key
	receiverNonce, err = t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}
	receiverPublicNonce, err := t.pubKeyFromSecretKey(receiverNonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
	}

	// parse out sender public blind and public nonce
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

	// Combine sender and receiver public blinds and nonces
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

	return
}

func (t *Wallet) NewInvoice(
	amount uint64,
	fee uint64,
	asset string,
) (
	slateBytes []byte,
	walletOutput *Output,
	savedSlate *SavedSlate,
	err error,
) {
	// create receiver output and remember its blinding factor and calculate its public key
	walletOutput, outputBlind, err := t.newOutput(amount, core.PlainOutput, asset, OutputUnconfirmed)
	if err != nil {
		err = errors.Wrap(err, "cannot create receiver output")
		return
	}

	slateBytes, savedSlate, err = t.newSlate(nil, []core.Output{walletOutput.Output}, amount, fee, asset, outputBlind[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create newSlate")
		return
	}

	return
}

func (t *Wallet) NewReceive(
	senderSlateBytes []byte,
) (
	receiverSlateBytes []byte,
	walletOutput *Output,
	savedSlate *SavedSlate,
	err error,
) {
	var slate = &Slate{}
	err = json.Unmarshal(senderSlateBytes, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal json to slate")
		return
	}

	value := uint64(slate.Amount)
	// fee := uint64(slate.Fee)

	// create receiver output and remember its blinding factor
	walletOutput, outputBlind, err := t.newOutput(value, core.PlainOutput, slate.Asset, OutputUnconfirmed)
	if err != nil {
		err = errors.Wrap(err, "cannot create receiver output")
		return
	}

	receiverNonce, err := t.respond(slate, walletOutput.Output, outputBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot respond to slate")
		return
	}

	receiverSlate := *slate
	receiverSlate.Status = SlateReceived

	receiverSlateBytes, err = json.Marshal(receiverSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	savedSlate = &SavedSlate{
		Slate: receiverSlate,
		Nonce: receiverNonce,
	}

	return
}

func (t *Wallet) NewPay(
	amount uint64,
	fee uint64,
	asset string,
	change uint64,
	walletInputs []Output,
	invoiceSlateBytes []byte,
) (
	slateBytes []byte,
	changeOutput *Output,
	savedSlate *SavedSlate,
	err error,
) {
	slateInputs, changeOutput, blindExcess, err := t.slateInputsAndChange(
		amount,
		fee,
		asset,
		change,
		walletInputs)
	if err != nil {
		err = errors.Wrap(err, "cannot create slate inputs and outputs")
		return
	}

	var slate = &Slate{}
	err = json.Unmarshal(invoiceSlateBytes, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal json to slate")
		return
	}

	slate.Transaction.Body.Inputs = slateInputs

	payerNonce, err := t.respond(slate, changeOutput.Output, blindExcess[:])
	if err != nil {
		err = errors.Wrap(err, "cannot respond to slate")
		return
	}

	payerSlate := slate
	payerSlate.Status = SlatePaid

	slateBytes, err = json.Marshal(payerSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	savedSlate = &SavedSlate{
		Slate: *payerSlate,
		Nonce: payerNonce,
	}

	return
}

func (t *Wallet) NewTransaction(responseSlateBytes []byte, senderSlate *SavedSlate) (ledgerTxBytes []byte, walletTx Transaction, err error) {
	// get secret keys from sender's responseSlate that has blind and secret nonces
	senderBlind := senderSlate.Blind[:]
	senderNonce := senderSlate.Nonce[:]
	// calculate public keys from secret keys
	senderPublicBlind, _ := t.pubKeyFromSecretKey(senderBlind)
	senderPublicNonce, _ := t.pubKeyFromSecretKey(senderNonce)

	// parse responseSlate
	var responseSlate = Slate{}
	err = json.Unmarshal(responseSlateBytes, &responseSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot unmarshal json to responseSlate")
		return
	}

	// parse out public blinds and nonces for both sender and receiver from the responseSlate
	if len(responseSlate.ParticipantData) != 2 {
		err = errors.New("expected 2 entries in ParticipantData")
		return
	}

	// get public keys from responseSlate
	senderPublicBlindFromReceiverSlate := t.context.PublicKeyFromHex(responseSlate.ParticipantData[0].PublicBlindExcess)
	senderPublicNonceFromReceiverSlate := t.context.PublicKeyFromHex(responseSlate.ParticipantData[0].PublicNonce)

	// verify that the response we've got from Receiver has Sender's public key and secret unchanged
	if (0 != bytes.Compare(senderPublicBlind.Bytes(t.context), senderPublicBlindFromReceiverSlate.Bytes(t.context))) ||
		(0 != bytes.Compare(senderPublicNonce.Bytes(t.context), senderPublicNonceFromReceiverSlate.Bytes(t.context))) {
		err = errors.Wrap(err, "public keys mismatch, calculated values are not the same as loaded from responseSlate")
		return
	}

	receiverPublicBlind := t.context.PublicKeyFromHex(responseSlate.ParticipantData[1].PublicBlindExcess)
	receiverPublicNonce := t.context.PublicKeyFromHex(responseSlate.ParticipantData[1].PublicNonce)

	// combine sender and receiver public blinds and nonces
	sumPublicBlinds, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicBlind, receiverPublicBlind})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicBlinds")
		return
	}
	sumPublicNonces, err := t.sumPubKeys([]*secp256k1.PublicKey{senderPublicNonce, receiverPublicNonce})
	if err != nil {
		err = errors.Wrap(err, "cannot get sumPublicNonces")
		return
	}

	// calculate message hash
	msg := ledger.KernelSignatureMessage(responseSlate.Transaction.Body.Kernels[0])

	// decode receiver's partial signature
	receiverPartSigBytes, err := hex.DecodeString(*responseSlate.ParticipantData[1].PartSig)
	if err != nil {
		err = errors.Wrap(err, "cannot decode receiverPartSigBytes from hex")
		return
	}
	receiverPartSig, err := secp256k1.AggsigSignaturePartialParse(receiverPartSigBytes)
	if err != nil {
		err = errors.Wrap(err, "cannot parse receiverPartialSig from bytes")
		return
	}

	// verify receiver's partial signature
	err = secp256k1.AggsigVerifyPartial(
		t.context,
		&receiverPartSig,
		sumPublicNonces,
		receiverPublicBlind,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify receiver partial signature")
		return
	}

	// calculate sender's partial signature
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
	err = secp256k1.AggsigVerifyPartial(
		t.context,
		&senderPartSig,
		sumPublicNonces,
		senderPublicBlind,
		sumPublicBlinds,
		msg,
	)
	if err != nil {
		err = errors.Wrap(err, "cannot verify sender partial signature")
		return
	}

	// add sender and receiver partial signatures
	finalSig, err := secp256k1.AggsigAddSignaturesSingle(
		t.context,
		[]*secp256k1.AggsigSignaturePartial{
			&senderPartSig,
			&receiverPartSig,
		},
		sumPublicNonces)
	if err != nil {
		err = errors.Wrap(err, "cannot add sender and receiver partial signatures")
		return
	}

	// verify final signature
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

	tx := responseSlate.Transaction

	// calculate kernel excess as a sum of commitments of inputs, outputs and kernel offset,
	// that would produce a *Commitment type result
	kernelExcess, err := ledger.CalculateExcess(t.context, &tx, uint64(responseSlate.Fee))
	if err != nil {
		err = errors.Wrap(err, "cannot calculate final kernel excess")
		return
	}

	excessPublicKey, err := secp256k1.CommitmentToPublicKey(t.context, kernelExcess)
	if err != nil {
		err = errors.Wrap(err, "excessPublicKey: CommitmentToPublicKey failed")
		return
	}

	// verify final sig with pk from excess
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
		ID:          responseSlate.ID,
	}

	ledgerTxBytes, err = json.Marshal(ledgerTx)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal ledgerTx to json")
		return
	}

	walletTx = Transaction{
		Transaction: ledgerTx,
		Status:      TransactionUnconfirmed,
		Asset:       responseSlate.Asset,
	}

	return
}

func (t *Wallet) newOutput(
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

func (t *Wallet) newSlate(slateInputs []core.Input, slateOutputs []core.Output,
	amount uint64, fee uint64, asset string, blind []byte) (slateBytes []byte, savedSlate *SavedSlate, err error) {

	// generate secret nonce
	nonce, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce")
		return
	}

	// generate random kernel offset
	kernelOffset, err := t.nonce()
	if err != nil {
		err = errors.Wrap(err, "cannot get nonce for kernelOffset")
		return
	}

	// subtract kernel offset from blinding excess
	sumBlinds, err := secp256k1.BlindSum(t.context, [][]byte{blind[:]}, [][]byte{kernelOffset[:]})
	if err != nil {
		err = errors.Wrap(err, "cannot BlindSum")
		return
	}

	publicBlindExcess, err := t.pubKeyFromSecretKey(sumBlinds[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicBlindExcess")
		return
	}

	publicNonce, err := t.pubKeyFromSecretKey(nonce[:])
	if err != nil {
		err = errors.Wrap(err, "cannot create publicNonce")
		return
	}

	coreSlate := &libwallet.Slate{
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

	slate := &Slate{
		Slate:  *coreSlate,
		Asset:  asset,
		Status: SlateSent,
	}

	savedSlate = &SavedSlate{
		Slate: *slate,
		Nonce: nonce,
		Blind: sumBlinds,
	}

	slateBytes, err = json.Marshal(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot marshal slate to json")
		return
	}

	return
}

func (t *Wallet) pubKeyFromSecretKey(sk32 []byte) (*secp256k1.PublicKey, error) {
	res, pk, err := secp256k1.EcPubkeyCreate(t.context, sk32)
	if res != 1 || pk == nil || err != nil {
		return nil, errors.Wrap(err, "cannot create pubKeyFromSecretKey")
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
