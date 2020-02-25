package multiasset

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/magiconair/properties/assert"
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
		expenses     []AssetBalance
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
		wantSenderSlate Slate
		wantErr         bool
	}{
		{name: "dummy", args: args{
			context: context,
			fee: AssetBalance{
				Asset:  sbercoin,
				Amount: 10,
			},

			walletInputs: []PrivateOutput{

				{SlateOutput: SlateOutput{
					PublicOutput: PublicOutput{
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
					AssetBlind: hex.EncodeToString(dummySecret[:]),
					Asset:      sbercoin,
				}, ValueBlind: dummySecret, Value: myInputValue, Status: wallet.OutputConfirmed},
			},
			purchases: []AssetBalance{{Asset: dummyToken, Amount: 10}},
			expenses:  []AssetBalance{{Asset: sbercoin, Amount: uint64(20)}},
		}, wantSlateBytes: nil, wantOutputs: nil, wantSenderSlate: Slate{}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slate := CreateSlate(tt.args.purchases, tt.args.expenses, tt.args.fee)

			outputs, err := slate.Process(context, tt.args.walletInputs, tt.args.purchases, tt.args.expenses)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSlate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			slateBytes, err := json.Marshal(slate.PublicSlate)
			fmt.Println(string(slateBytes))

			sbercoinOutput := outputs[0]
			assert.Equal(t, sbercoinOutput.Asset.Id, sbercoin.Id)
			assert.Equal(t, sbercoinOutput.Value, 70)

			purchaseOutput := outputs[1]
			assert.Equal(t, purchaseOutput.Value, 10)
			assert.Equal(t, purchaseOutput.Asset.Id, dummyToken.Id)

		})
	}
}
