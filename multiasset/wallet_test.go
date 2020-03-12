package multiasset

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/magiconair/properties/assert"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"reflect"
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
	sbercoin := newAsset("sbercoin")
	dummyToken := newAsset("dummyToken")
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
				Asset: sbercoin,
				Value: 10,
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
			purchases: []AssetBalance{{Asset: dummyToken, Value: 10}},
			expenses:  []AssetBalance{{Asset: sbercoin, Value: uint64(20)}},
		}, wantSlateBytes: nil, wantOutputs: nil, wantSenderSlate: Slate{}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slate := CreateSlate(tt.args.purchases, tt.args.expenses, tt.args.fee)

			_, outputs, err := slate.Process(context, tt.args.walletInputs, tt.args.purchases, tt.args.expenses)
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

func Test_calculateOutputValues(t *testing.T) {
	type args struct {
		fee          AssetBalance
		walletInputs []PrivateOutput
		spends       []AssetBalance
	}
	apple := newAsset("apple")
	dummySecret := secp256k1.Random256()
	myOutput := PrivateOutput{
		SlateOutput: SlateOutput{
			PublicOutput: PublicOutput{},
			AssetBlind:   hex.EncodeToString(dummySecret[:]),
			Asset:        apple,
		},
		ValueBlind: dummySecret,
		Value:      100,
		Status:     wallet.OutputConfirmed}

	tests := []struct {
		name             string
		args             args
		wantSpentInputs  []SlateInput
		wantInputBlinds  [][]byte
		wantChangeValues map[Asset]uint64
		wantErr          bool
	}{
		{name: "simple",
			args: struct {
				fee          AssetBalance
				walletInputs []PrivateOutput
				spends       []AssetBalance
			}{
				fee: AssetBalance{
					Asset: apple,
					Value: 1,
				},
				walletInputs: []PrivateOutput{myOutput},
				spends: []AssetBalance{{
					Asset: apple,
					Value: 10,
				}, {
					Asset: apple,
					Value: 10,
				}},
			},
			wantSpentInputs: []SlateInput{{
				Input:      myOutput.Input,
				Asset:      myOutput.Asset,
				AssetBlind: myOutput.AssetBlind,
			}},
			wantInputBlinds:  [][]byte{dummySecret[:]},
			wantChangeValues: map[Asset]uint64{apple: 79},
			wantErr:          false,
		},
		{name: "multiple outputs",
			args: struct {
				fee          AssetBalance
				walletInputs []PrivateOutput
				spends       []AssetBalance
			}{
				fee: AssetBalance{
					Asset: apple,
					Value: 1,
				},
				walletInputs: []PrivateOutput{myOutput},
				spends: []AssetBalance{{
					Asset: apple,
					Value: 10,
				}},
			},
			wantSpentInputs: []SlateInput{{
				Input:      myOutput.Input,
				Asset:      myOutput.Asset,
				AssetBlind: myOutput.AssetBlind,
			}},
			wantInputBlinds:  [][]byte{dummySecret[:]},
			wantChangeValues: map[Asset]uint64{apple: 89},
			wantErr:          false,
		},
		{name: "insufficient funds",
			args: struct {
				fee          AssetBalance
				walletInputs []PrivateOutput
				spends       []AssetBalance
			}{
				fee: AssetBalance{
					Asset: apple,
					Value: 1,
				},
				walletInputs: []PrivateOutput{myOutput},
				spends: []AssetBalance{{
					Asset: apple,
					Value: 100,
				}},
			},
			wantSpentInputs:  nil,
			wantInputBlinds:  nil,
			wantChangeValues: nil,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSpentInputs, gotInputBlinds, gotChangeValues, err := calculateOutputValues(tt.args.fee, tt.args.walletInputs, tt.args.spends)
			if (err != nil) != tt.wantErr {
				t.Errorf("calculateOutputValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSpentInputs, tt.wantSpentInputs) {
				t.Errorf("calculateOutputValues() gotSpentInputs = %v, want %v", gotSpentInputs, tt.wantSpentInputs)
			}
			if !reflect.DeepEqual(gotInputBlinds, tt.wantInputBlinds) {
				t.Errorf("calculateOutputValues() gotInputBlinds = %v, want %v", gotInputBlinds, tt.wantInputBlinds)
			}
			if !reflect.DeepEqual(gotChangeValues, tt.wantChangeValues) {
				t.Errorf("calculateOutputValues() gotChangeValues = %v, want %v", gotChangeValues, tt.wantChangeValues)
			}
		})
	}
}
