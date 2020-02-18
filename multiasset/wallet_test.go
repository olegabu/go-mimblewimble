package multiasset

import (
	"encoding/json"
	"fmt"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"testing"
)

func TestCreateSlate(t *testing.T) {
	type args struct {
		context      *secp256k1.Context
		fee          AssetBalance
		walletInputs []PrivateOutput
		purchases    []AssetBalance
		offers       []AssetBalance
	}

	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	myInputValue := uint64(100)
	dummySecret := secp256k1.Random256()
	sbercoin, _ := newAsset("sbercoin")
	dummyToken, _ := newAsset("dummyToken")
	assetCommitment, _ := secp256k1.GeneratorGenerateBlinded(context, sbercoin.seed(), dummySecret[:])
	valueCommitment, _ := secp256k1.Commit(context, dummySecret[:], myInputValue, assetCommitment, &secp256k1.GeneratorG)

	tests := []struct {
		name            string
		args            args
		wantSlateBytes  []byte
		wantOutputs     []PrivateOutput
		wantSenderSlate SenderSlate
		wantErr         bool
	}{
		{name: "dummy", args: args{
			context: context,
			fee: AssetBalance{
				asset:  sbercoin,
				amount: 10,
			},

			walletInputs: []PrivateOutput{
				{PublicOutput: PublicOutput{
					Input: Input{
						Features: 0,
						Commit: Commitment{
							ValueCommitment: valueCommitment.Hex(context),
							AssetCommitment: assetCommitment.String(),
						},
					},
					Proof:           "",
					SurjectionProof: "",
				},
					ValueBlind: dummySecret,
					AssetBlind: dummySecret,
					Value:      myInputValue,
					Status:     wallet.OutputConfirmed,
					Asset:      sbercoin},
			},
			purchases: []AssetBalance{{asset: dummyToken, amount: 10}},
			offers:    []AssetBalance{{asset: sbercoin, amount: uint64(20)}},
		}, wantSlateBytes: nil, wantOutputs: nil, wantSenderSlate: SenderSlate{}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, slate, err := CreateSlate(tt.args.context, tt.args.fee, tt.args.walletInputs, tt.args.purchases, tt.args.offers)
			slateBytes, err := json.Marshal(slate)
			fmt.Printf("%v", string(slateBytes))
			//e := json.NewEncoder( log.Writer())
			//_ = e.Encode(slate)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSlate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			//if  {
			//
			//}
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
