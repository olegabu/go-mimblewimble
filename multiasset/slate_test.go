package multiasset

import (
	"fmt"
	"github.com/magiconair/properties/assert"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
	"testing"
)

func TestSlate_Process(t *testing.T) {

	type args struct {
		context      *secp256k1.Context
		walletInputs []PrivateOutput
		purchases    []AssetBalance
		expenses     []AssetBalance
	}

	apples := newAsset("apples")
	oranges := newAsset("oranges")

	dummySecret := secp256k1.Random256()
	aliceOldOutput := PrivateOutput{
		SlateOutput: SlateOutput{
			PublicOutput: PublicOutput{},
			AssetBlind:   "",
			Asset:        apples,
		},
		ValueBlind: dummySecret,
		Value:      100,
		Status:     wallet.OutputUnconfirmed,
	}
	alicePurchases := []AssetBalance{{
		Asset: oranges,
		Value: 10,
	}}

	aliceExpenses := []AssetBalance{{
		Asset: apples,
		Value: 10,
	}}

	fee := AssetBalance{
		Asset: apples,
		Value: 1,
	}
	aliceSlate := CreateSlate(alicePurchases, aliceExpenses, fee)
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	walletInputs := []PrivateOutput{aliceOldOutput}
	bobsSlate := CreateSlate(alicePurchases, aliceExpenses, fee)
	_, _, _ = bobsSlate.Process(context, walletInputs, alicePurchases, aliceExpenses)

	bobsOutput := PrivateOutput{
		SlateOutput: SlateOutput{
			PublicOutput: PublicOutput{},
			AssetBlind:   "",
			Asset:        oranges,
		},
		ValueBlind: [32]byte{},
		Value:      11,
		Status:     wallet.OutputConfirmed,
	}
	tests := []struct {
		name        string
		slate       Slate
		args        args
		wantOutputs []AssetBalance
		wantErr     bool
	}{
		{name: "First round by Alice",
			slate: aliceSlate,
			args: struct {
				context      *secp256k1.Context
				walletInputs []PrivateOutput
				purchases    []AssetBalance
				expenses     []AssetBalance
			}{
				context:      context,
				walletInputs: walletInputs,
				purchases:    alicePurchases,
				expenses:     aliceExpenses,
			},
			wantOutputs: []AssetBalance{
				//{Asset: apples, Value: 10},
				{Asset: apples, Value: 89},
				{Asset: oranges, Value: 10}},
			wantErr: false},
		{name: "Bob's round 2", slate: bobsSlate, args: struct {
			context      *secp256k1.Context
			walletInputs []PrivateOutput
			purchases    []AssetBalance
			expenses     []AssetBalance
		}{context: context,
			walletInputs: []PrivateOutput{bobsOutput},
			purchases:    aliceExpenses,
			expenses:     alicePurchases},
			wantOutputs: []AssetBalance{
				{Asset: oranges, Value: 1},
				{Asset: apples, Value: uint64(10)},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slate := &tt.slate
			_, outputs, err := slate.Process(tt.args.context, tt.args.walletInputs, tt.args.purchases, tt.args.expenses)
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
