package multiasset

import (
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"testing"
)

func TestCreateSlate(t *testing.T) {
	type args struct {
		context      *secp256k1.Context
		fee          AssetBalance
		walletInputs []privateOutput
		purchases    []AssetBalance
		offers       []AssetBalance
	}

	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)

	dummySecret := secp256k1.Random256()
	sbercoin := newAsset("sbercoin")
	dummyToken := newAsset("dummyToken")
	H, _ := secp256k1.GeneratorGenerateBlinded(context, sbercoin.Id[:], dummySecret[:])
	assetCommitment, _ := secp256k1.Commit(context, dummySecret[:], 1, H, &secp256k1.GeneratorG)
	tests := []struct {
		name            string
		args            args
		wantSlateBytes  []byte
		wantOutputs     []privateOutput
		wantSenderSlate SenderSlate
		wantErr         bool
	}{
		{name: "dummy", args: args{
			context: context,
			fee: AssetBalance{
				asset:  sbercoin,
				amount: 10,
			},

			walletInputs: []privateOutput{
				{publicOutput: publicOutput{
					Input: Input{
						Features: 0,
						Commit: Commitment{
							ValueCommitment: "",
							AssetCommitment: (*assetCommitment).Hex(context),
						},
					},
					Proof:           "",
					SurjectionProof: "",
				},
					ValueBlind: dummySecret,
					AssetBlind: dummySecret,
					Value:      100,
					Status:     wallet.OutputConfirmed,
					Asset:      sbercoin},
			},
			purchases: []AssetBalance{{asset: dummyToken, amount: 10}},
			offers:    []AssetBalance{{asset: sbercoin, amount: uint64(20)}},
		}, wantSlateBytes: nil, wantOutputs: nil, wantSenderSlate: SenderSlate{}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := CreateSlate(tt.args.context, tt.args.fee, tt.args.walletInputs, tt.args.purchases, tt.args.offers)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSlate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if !reflect.DeepEqual(gotSlateBytes, tt.wantSlateBytes) {
			//	t.Errorf("CreateSlate() gotSlateBytes = %v, want %v", gotSlateBytes, tt.wantSlateBytes)
			//}
			//if !reflect.DeepEqual(gotOutputs, tt.wantOutputs) {
			//	t.Errorf("CreateSlate() gotOutputs = %v, want %v", gotOutputs, tt.wantOutputs)
			//}
			//if !reflect.DeepEqual(gotSenderSlate, tt.wantSenderSlate) {
			//	t.Errorf("CreateSlate() gotSenderSlate = %v, want %v", gotSenderSlate, tt.wantSenderSlate)
			//}
		})
	}
}
