package multiasset

import (
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func CreateSlate(
	context *secp256k1.Context,
	fee AssetBalance,
	walletInputs []privateOutput,
	purchase []AssetBalance,
	offers []AssetBalance) (
	slateBytes []byte,
	changeOutput *privateOutput,
	senderSlate SenderSlate,
	err error,
) {
	// create a local context object if it's not provided in parameters
	if context == nil {
		if context, err = secp256k1.ContextCreate(secp256k1.ContextBoth); err != nil {
			return nil, nil, SenderSlate{}, errors.Wrap(err, "ContextCreate failed")
		}
		defer secp256k1.ContextDestroy(context)
	}

	offerBalance := make(map[string]uint64)

	offerBalance[fee.asset.id] += fee.amount

	for _, offer := range offers {
		offerBalance[offer.asset.id] += offer.amount
	}

	myBalance := make(map[string]uint64)
	for _, input := range walletInputs {
		myBalance[input.Asset.id] += input.Value
	}

	for assetId, value := range offerBalance {
		if myBalance[assetId] < value {
			err = errors.New("insufficient funds")
		}
	}

	//slate := Slate{
	//	GrinSlate: GrinSlate{
	//		VersionInfo: libwallet.VersionCompatInfo{
	//			Version:            3,
	//			OrigVersion:        3,
	//			BlockHeaderVersion: 2,
	//		},
	//		NumParticipants: 2,
	//		ID:              uuid.UUID{},
	//		Transaction:     LedgerTransaction{
	//			Offset: hex.EncodeToString(kernelOffset[:]),
	//			Body: TransactionBody{
	//				Inputs:  slateInputs,
	//				Outputs: slateOutputs,
	//				Kernels: []core.TxKernel{
	//					{
	//						Features:   core.PlainKernel,
	//						Fee:        core.Uint64(fee),
	//						LockHeight: 0,
	//						Excess:     "",
	//						ExcessSig:  "",
	//					},
	//				},
	//			},
	//			ID: uuid.UUID{},
	//		},
	//		Amount:          0,
	//		Fee:             0,
	//		Height:          0,
	//		LockHeight:      0,
	//		TTLCutoffHeight: nil,
	//		ParticipantData: []libwallet.ParticipantData{{
	//			ID:                0,
	//			PublicBlindExcess: publicBlindExcess.Hex(context),
	//			PublicNonce:       publicNonce.Hex(context),
	//			PartSig:           nil,
	//			Message:           nil,
	//			MessageSig:        nil,
	//		}},
	//		PaymentProof:    nil,
	//	},
	//	Asset:     "",
	//	Status:    0,
	//}
	//
	//senderSlate = SenderSlate{
	//	Slate:           Slate{},
	//	SumSenderBlinds: [32]byte{},
	//	SenderNonce:     [32]byte{},
	//}

	return
}
