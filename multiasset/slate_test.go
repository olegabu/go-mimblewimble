package multiasset

import (
	"encoding/hex"
	"fmt"
	"github.com/magiconair/properties/assert"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"testing"
)

func TestSlate_Process(t *testing.T) {

	type args struct {
		wallet    Wallet
		purchases []AssetBalance
		expenses  []AssetBalance
		fee       AssetBalance
	}

	apples := newAsset("apples")
	oranges := newAsset("oranges")
	//oranges := newAsset("oranges")

	dummySecret := secp256k1.Random256()

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)

	wallet := Wallet{
		inputs: []PrivateOutput{
			{
				SlateOutput: SlateOutput{
					PublicOutput: PublicOutput{},
					AssetBlind:   hex.EncodeToString(dummySecret[:]),
					Asset:        apples,
				},
				ValueBlind: dummySecret,
				Value:      100,
				Status:     wallet.OutputConfirmed,
			},
		},
		context: ctx,
	}
	tests := []struct {
		name        string
		args        args
		wantOutputs []AssetBalance
		wantErr     bool
	}{
		{name: "1st round", args: struct {
			wallet    Wallet
			purchases []AssetBalance
			expenses  []AssetBalance
			fee       AssetBalance
		}{wallet: wallet,
			purchases: []AssetBalance{{Asset: oranges, Value: 1}},
			expenses:  []AssetBalance{{Asset: apples, Value: 1}}},
			wantOutputs: []AssetBalance{{Asset: apples, Value: 99}, {Asset: oranges, Value: 1}},
			wantErr:     false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, outputs, err := wallet.CreateSlate(tt.args.purchases, tt.args.expenses, tt.args.fee)
			if (err != nil) != tt.wantErr {
				t.Errorf("Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if !reflect.DeepEqual(gotPrivateOutputs, tt.wantPrivateOutputs) {
			//	t.Errorf("Process() gotPrivateOutputs = %v, want %v", gotPrivateOutputs, tt.wantPrivateOutputs)
			//}

			//We can't directly compare outputs, because of random blinding factors
			assert.Equal(t, len(outputs), len(tt.wantOutputs))
			found := false
			for _, wantedOutput := range tt.wantOutputs {
			Got:
				for _, gotOutput := range outputs {
					if wantedOutput.Asset == gotOutput.Asset && wantedOutput.Value == gotOutput.Value {
						found = true
						break Got
					}
				}
				assert.Equal(t, found, true, fmt.Sprintf("output %v was not found among created outputs %v", wantedOutput, outputs))
			}
		})
	}
}

func TestPrivateOutput_tweakedExcess(t *testing.T) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	dummySecret := "e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9"
	dummySecretByteSlice, _ := hex.DecodeString(dummySecret)
	var dummySecretBytes [32]byte
	copy(dummySecretBytes[:], dummySecretByteSlice)
	apples := newAsset("apples")
	//dummySecret := secp256k1.Random256()
	type args struct {
		ctx *secp256k1.Context
	}
	tests := []struct {
		name       string
		output     PrivateOutput
		args       args
		wantExcess []byte
		wantErr    bool
	}{
		{name: "simple", output: PrivateOutput{
			SlateOutput: SlateOutput{
				PublicOutput: PublicOutput{},
				AssetBlind:   dummySecret, //hex.EncodeToString(dummySecret[:]),
				Asset:        apples,
			},
			ValueBlind: dummySecretBytes,
			Value:      11,
			Status:     0,
		}, args: args{ctx: ctx}, wantExcess: []byte{}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := tt.output.tweakedExcess()
			if (err != nil) != tt.wantErr {
				t.Errorf("tweakedExcess() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if !reflect.DeepEqual(gotExcess, tt.wantExcess) {
			//	t.Errorf("tweakedExcess() gotExcess = %v, want %v", gotExcess, tt.wantExcess)
			//}
		})
	}
}
