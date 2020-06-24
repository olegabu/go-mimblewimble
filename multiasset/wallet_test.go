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
		context   *secp256k1.Context
		fee       AssetBalance
		wallet    Wallet
		purchases []AssetBalance
		expenses  []AssetBalance
	}

	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	myInputValue := uint64(100)
	dummySecret := secp256k1.Random256()
	sbercoin := newAsset("sbercoin")
	dummyToken := newAsset("dummyToken")
	assetCommitment, _ := secp256k1.GeneratorGenerateBlinded(context, sbercoin.seed(), dummySecret[:])
	valueCommitment, _ := secp256k1.Commit(context, dummySecret[:], myInputValue, assetCommitment, &secp256k1.GeneratorG)
	w := Wallet{
		inputs: []PrivateOutput{

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
		context: context,
	}

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

			wallet:    w,
			purchases: []AssetBalance{{Asset: dummyToken, Value: 10}},
			expenses:  []AssetBalance{{Asset: sbercoin, Value: uint64(20)}},
		}, wantSlateBytes: nil, wantOutputs: nil, wantSenderSlate: Slate{}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//slate := CreateSlate(tt.args.purchases, tt.args.expenses, tt.args.fee)

			slate, outputs, err := w.CreateSlate(tt.args.purchases, tt.args.expenses, tt.args.fee)
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
		fee    AssetBalance
		wallet Wallet
		spends []AssetBalance
	}
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
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

	wallet := Wallet{
		inputs:  []PrivateOutput{myOutput},
		context: context,
	}
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
				fee    AssetBalance
				wallet Wallet
				spends []AssetBalance
			}{
				fee: AssetBalance{
					Asset: apple,
					Value: 1,
				},
				wallet: wallet,
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
			args: args{
				fee: AssetBalance{
					Asset: apple,
					Value: 1,
				},
				wallet: wallet,
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
			wantChangeValues: map[Asset]uint64{apple: 89},
			wantErr:          false,
		},
		{name: "insufficient funds",
			args: args{
				fee: AssetBalance{
					Asset: apple,
					Value: 1,
				},
				wallet: wallet,
				spends: []AssetBalance{{
					Asset: apple,
					Value: 100,
				}},
			},
			wantSpentInputs:  nil,
			wantChangeValues: nil,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSpentInputs, gotChangeValues, err := wallet.calculateOutputValues(tt.args.fee, tt.args.spends)
			if (err != nil) != tt.wantErr {
				t.Errorf("calculateOutputValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSpentInputs, tt.wantSpentInputs) {
				t.Errorf("calculateOutputValues() gotSpentInputs = %v, want %v", gotSpentInputs, tt.wantSpentInputs)
			}
			if !reflect.DeepEqual(gotChangeValues, tt.wantChangeValues) {
				t.Errorf("calculateOutputValues() gotChangeValues = %v, want %v", gotChangeValues, tt.wantChangeValues)
			}
		})
	}
}

func testTally(t *testing.T) {
	apple := newAsset("apple")
	dummySecret := secp256k1.Random256()
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	inputAssetGenerator, _ := secp256k1.GeneratorGenerateBlinded(ctx, apple.seed(), dummySecret[:])
	inputAssetCommitment := secp256k1.GeneratorSerialize(ctx, inputAssetGenerator)
	inputValueCommitment, _ := secp256k1.Commit(ctx, dummySecret[:], 100, inputAssetGenerator, &secp256k1.GeneratorG)
	inputValueCommitmentBytes, _ := secp256k1.CommitmentSerialize(ctx, inputValueCommitment)
	myInput := PrivateOutput{
		SlateOutput: SlateOutput{
			PublicOutput: PublicOutput{
				Input: Input{
					Features: 0,
					Commit: Commitment{
						ValueCommitment: hex.EncodeToString(inputValueCommitmentBytes[:]),
						AssetCommitment: hex.EncodeToString(inputAssetCommitment[:]),
					},
				},
				Proof:           "",
				SurjectionProof: "",
			},
			AssetBlind: hex.EncodeToString(dummySecret[:]),
			Asset:      apple,
		},
		ValueBlind: dummySecret,
		Value:      100,
		Status:     0,
	}

	myInputAsJson, _ := json.Marshal(myInput)
	fmt.Printf("%v %v", hex.EncodeToString(dummySecret[:]), myInputAsJson)

	alice := Wallet{
		inputs:  []PrivateOutput{myInput},
		context: ctx,
	}

	slate, privateOutputs, err := alice.CreateSlate(
		[]AssetBalance{{ //purchases
			apple,
			10,
		}},
		[]AssetBalance{{ //expenses
			apple,
			10,
		}},
		AssetBalance{ //fee
			apple,
			0,
		})
	if err != nil {
		t.Error(err)
	}

	for _, privateOutput := range privateOutputs {
		privateOutputsExcess = secp256k1.EcPrivkeyTweakAdd()
	}

	inputExcess, _ = myInput.tweakedExcess()

	inputs := slate.Transaction.Body.Inputs
	outputs := slate.Transaction.Body.Outputs
}
