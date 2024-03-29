package wallet

import (
	"encoding/json"
	"fmt"
	"github.com/olegabu/go-mimblewimble/pkg/ledger"
	"os"
	"testing"

	"github.com/blockcypher/libgrin/core"
	"github.com/stretchr/testify/assert"

	"github.com/olegabu/go-secp256k1-zkp"
)

func TestSlateSendReceive(t *testing.T) {
	w := newTestWallet(t)
	defer w.Close()

	inputValue := uint64(300)
	amount := uint64(200)
	fee := uint64(0)
	asset := "cash"

	change := inputValue - amount - fee

	input1, _, err := w.newOutput(uint64(1), core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	input2, _, err := w.newOutput(inputValue-1, core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	inputs := []Output{*input1, *input2}

	senderSlateBytes, _, senderSavedSlate, err := w.NewSlate(amount, fee, asset, change, inputs, 0, "")
	assert.NoError(t, err)
	assert.NotNil(t, senderSlateBytes)
	fmt.Printf("send %s\n", string(senderSlateBytes))

	responseSlateBytes, _, responseSavedSlate, err := w.NewResponse(0, fee, "", 0, nil, amount, asset, &senderSavedSlate.Slate)
	assert.NoError(t, err)
	assert.NotNil(t, responseSlateBytes)
	fmt.Printf("resp %s\n", string(responseSlateBytes))

	txBytes, tx, err := w.NewTransaction(&responseSavedSlate.Slate, senderSavedSlate)
	assert.NotNil(t, txBytes)
	assert.NotNil(t, tx)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(txBytes))

	tr, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
	assert.NotNil(t, tr)
}

func TestSlateExchange(t *testing.T) {
	w := newTestWallet(t)
	defer w.Close()

	fee := uint64(0)

	sendInputValue := uint64(300)
	sendAmount := uint64(200)
	sendAsset := "cash"
	sendChange := sendInputValue - sendAmount - fee

	receiveAmount := uint64(100)
	receiveAsset := "apple"

	sendInput1, _, err := w.newOutput(uint64(1), core.CoinbaseOutput, sendAsset, OutputUnconfirmed)
	assert.NoError(t, err)
	sendInput2, _, err := w.newOutput(sendInputValue-1, core.CoinbaseOutput, sendAsset, OutputUnconfirmed)
	assert.NoError(t, err)
	sendInputs := []Output{*sendInput1, *sendInput2}

	senderSlateBytes, _, senderSavedSlate, err := w.NewSlate(sendAmount, fee, sendAsset, sendChange, sendInputs, receiveAmount, receiveAsset)
	assert.NoError(t, err)
	assert.NotNil(t, senderSlateBytes)
	fmt.Printf("send %s\n", string(senderSlateBytes))

	receiveInputValue := uint64(200)
	receiveChange := receiveInputValue - receiveAmount - fee

	receiveInput1, _, err := w.newOutput(uint64(1), core.CoinbaseOutput, receiveAsset, OutputUnconfirmed)
	assert.NoError(t, err)
	receiveInput2, _, err := w.newOutput(receiveInputValue-1, core.CoinbaseOutput, receiveAsset, OutputUnconfirmed)
	assert.NoError(t, err)
	receiveInputs := []Output{*receiveInput1, *receiveInput2}

	responseSlateBytes, _, responseSavedSlate, err := w.NewResponse(receiveAmount, fee, receiveAsset, receiveChange, receiveInputs, sendAmount, sendAsset, &senderSavedSlate.Slate)
	assert.NoError(t, err)
	assert.NotNil(t, responseSlateBytes)
	fmt.Printf("resp %s\n", string(responseSlateBytes))

	txBytes, tx, err := w.NewTransaction(&responseSavedSlate.Slate, senderSavedSlate)
	assert.NotNil(t, txBytes)
	assert.NotNil(t, tx)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(txBytes))

	tr, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
	assert.NotNil(t, tr)

	// 4 inputs: 299+1 cash 199+1 apple
	// 4 outputs: 200 cash, 100 cash change and 100 apple 100, apple change
	assert.Equal(t, 4, len(tx.Body.Inputs))
	assert.Equal(t, 4, len(tx.Body.Outputs))
}

func newTestWallet(t *testing.T) (w *Wallet) {
	dir := testDbDir()

	err := os.RemoveAll(dir)
	assert.NoError(t, err)

	w, err = NewWalletWithoutMasterKey(dir)
	assert.NoError(t, err)

	_, err = w.InitMasterKey("digital fatigue essay pretty number firm calm skirt exhibit seat able phrase")
	assert.NoError(t, err)

	return
}

func TestNewExchange(t *testing.T) {
	w := newTestWallet(t)
	defer w.Close()

	inputValue := uint64(300)
	amount := uint64(200)
	fee := uint64(0)
	asset := "cash"

	change := inputValue - amount - fee

	input1, _, err := w.newOutput(uint64(1), core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	input2, _, err := w.newOutput(inputValue-1, core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	inputs := []Output{*input1, *input2}

	exchangeAmount := uint64(100)
	exchangeAsset := "apple"

	slateBytes, walletOutput, savedSlate, err := w.NewSlate(amount, fee, asset, change, inputs, exchangeAmount, exchangeAsset)
	assert.NoError(t, err)
	assert.NotNil(t, slateBytes)
	assert.NotNil(t, walletOutput)
	assert.NotNil(t, savedSlate)
	fmt.Printf("exchange %s\n", string(slateBytes))
}

func TestSlateInvoicePay(t *testing.T) {
	w := newTestWallet(t)
	defer w.Close()

	inputValue := uint64(300)
	amount := uint64(200)
	fee := uint64(0)
	asset := "cash"

	invoiceSlateBytes, walletOutput, invoiceSavedSlate, err := w.NewSlate(0, fee, "", 0, nil, amount, asset)
	assert.NoError(t, err)
	assert.NotNil(t, invoiceSlateBytes)
	assert.NotNil(t, walletOutput)
	assert.NotNil(t, invoiceSavedSlate)
	fmt.Printf("invoice %s\n", string(invoiceSlateBytes))

	change := inputValue - amount - fee

	input1, _, err := w.newOutput(uint64(1), core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	input2, _, err := w.newOutput(inputValue-1, core.CoinbaseOutput, asset, OutputUnconfirmed)
	assert.NoError(t, err)
	inputs := []Output{*input1, *input2}

	paySlateBytes, changeOutput, paySavedSlate, err := w.NewResponse(amount, fee, asset, change, inputs, 0, "", &invoiceSavedSlate.Slate)
	assert.NoError(t, err)
	assert.NotNil(t, paySlateBytes)
	assert.NotNil(t, changeOutput)
	assert.NotNil(t, paySavedSlate)
	fmt.Printf("pay %s\n", string(paySlateBytes))

	txBytes, tx, err := w.NewTransaction(&paySavedSlate.Slate, invoiceSavedSlate)
	assert.NotNil(t, txBytes)
	assert.NotNil(t, tx)
	assert.NoError(t, err)
	fmt.Printf("tran %s\n", string(txBytes))

	tr, err := ledger.ValidateTransactionBytes(txBytes)
	assert.NoError(t, err)
	assert.NotNil(t, tr)
}

func TestExcess(t *testing.T) {
	context, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	slate := new(Slate)
	err := json.Unmarshal(slateFinal, slate)
	assert.NoError(t, err)

	fee := uint64(slate.Fee)
	kex, err := ledger.CalculateExcess(context, &slate.Transaction, fee)
	assert.NoError(t, err)
	fmt.Printf("ledger.CalculateExcess: %s\n", kex.String())

	kex0 := slate.Transaction.Body.Kernels[0].Excess
	fmt.Printf("slate.Transaction.Body.Kernels[0].Excess: %s\n", kex0)

	assert.Equal(t, kex0, kex.String())
}

func TestNewOutput(t *testing.T) {
	w := newTestWallet(t)
	defer w.Close()

	w.newOutput(3, core.PlainOutput, "cash", OutputLocked)
}

var slateFinal []byte = []byte(`{
    "version_info": {
        "version": 3,
        "orig_version": 3,
        "block_header_version": 2
    },
    "num_participants": 2,
    "id": "53a7a720-afa9-48de-99e1-3cbb27d89d82",
    "tx": {
        "offset": "fb6cfc60871c81e72e820c6900e6b7e16e4895f20fd527d5d4f327ffa2978776",
        "body": {
            "inputs": [{
                "features": "Plain",
                "commit": "0887798757d208b3f1f597daee46775027eb74d487cc1f0d99d9a6ff2c8266788f"
            }, {
                "features": "Plain",
                "commit": "088e163d3771f5af6b45fa90d4af36460ca0f536b3d3c629418cdc6ba14841f912"
            }],
            "outputs": [{
                "features": "Plain",
                "commit": "08f9b80af18781bba1df2bb69398abba15d4cbc91a9ed12f4102a5366077838672",
                "proof": "a38409352bd19adab834d500cf69b322f6a0ca1b8ac404eee4b7e8245af7732d337a59c33b68364245269f8fe5340262acfb3b97c2382cc43ffd54a1a4ef47cd036c4d2aac2a5f7801a77517328aec086614b54a26cb5ec60b0fdedfaccbbe507f91d976b1bca75e8142c90ea3f2897e3bf615b4238eaa65f07a57edb8c27d95f7b896f0002c890a2642bfc6f55a5cb459d4c922a5403a9e13b5873f3d56f783d44f742fc43eefd9b43b33930d90eddc41316b8c20f6c83ba652dafbbd520b1a2a03d0938902b58feb797f6353d151d359fe3c66188226da2bfbdedaadf66460bcf7d73fdb5975d6f88a0987c7f3ee1f8760e520810fd8dcb65da6f42b3f0bd567ae9d2db925da198b25386fb001381f44c570514c9b7ae343c0822521dbfc7f4060287e0c4a60a49cf4f62893ae81649395c0585b5dbaa7295f53b0a36ad3144eff7dfd01a7c5a152bf5f8f025081828060155b4f05bddcea0dc5df0df0e675041c027ee58e7e1eafd1300541ef051bce4c71a5c1c3f151f057e6a0e25bf363cac9262e4d1412e1b0e45c5479cd1e8d42720a4002b69fb2771ad724f486d9b46466c2ed31b0c5c0583a7540add002f20363a74a6e006939b0a1083a1273053491b08e9c95f90b2da264114790cc4904baf59ca4418c067d2e4c92f09a90187a51d85c672493f76378a703919f1c3d26dd5fe5a2fac5621299bdd524aa3a41387297a3d7a2f0f15d2c4149272db6faa512115b9b621289b4cda99fe97c441fef4d1a0f09157d0cb7955a81ac18df28a63963f520fc456ca00317ee2455808535fc514b313842a5be8929c82a08ed26a93985d57805ce8a0ca6173bdff0c2f0d0f7f80864e5b033033727ff68de792004512a0a75eab356e10de073d49d5435d308551ae0d2b4b5dadaced40ba5861443896dd776774a15d78894c351de0caa7e449236"
            }, {
                "features": "Plain",
                "commit": "081240e3e9235f3503e4ad6a93f403e73a263f36774eb2b9c01683c2b43db0f1cb",
                "proof": "b170b6d9e3486075d8e4f8a62188c075aaace789c1d924595a12dfabbc3b31563febac02441bdceb4d847a8f922a426a6b4381f23e18a279971cbc0b4f3aa2d10ba177d5cd31c570113ccb35418a9881db1d7e4a0a1031a942a38d342fc7a9a89ac8637f1782647e4605ea2cf042953ae0faf860d8d3fb20c7a13b02240d8a3d8f9ec32cbf3a24d21a84c6b6701b2fd0e353499b4154c570765d8cf7989babe0313712340dc39c3b1c9e07d3951e0fbd2654817f74b4cd20014a9cb7161d4c7de99dacd5bd0e93fed4d7f804038beabaaa3545535a108677a62c9bac2ed781234aca76253f9c0554b835e2f9a18b761629709add3404413d6345663f1b840f58f017a354bee75891e98940df30ed120838b86493c35f80d760373ed8213d39f3e850c268c153243b614af3816acf16df1a8bc3c99eb2d2f0daec5479508133caf86dfb0e73818c14af922682a40cb0e6088411db337637086cccc80cc2dd755471bc0391fd30d4ab60834adcd7aad4d2c9c815eff464a1e19910f2d30338f25c5bd0bc9fcc2e07cd1d67b469cee81d038e0cdbe92068c5c43c4bc648a8497366f9f4a852e9b95c5e284e22090b24ee940d878e9b95e4397ee9f3dd97897c52a180231d8b56ce59d2b1285d68f4b5eae5207509aae358ef56dc17ee484dcb7d2bd6df6196502482d953683d3b044c2b9e467dac7eba6870553afee8ccfec4420abada73911033322fd7d6547b4d86f412c993564b7930bb728e2d6ec23a6dbdf27756e99bd55f4d1b00836b7402f51549da119e9e0d5391389787c017ab1b8dfd4cc4023bd3057f19814876ea95ddbeb472a733c802ae6b3db1f4798b181c8b28cc142c9da03747cb596d7343a6a4dcd7dcdfe3e298c3980156a221d9081ed08789b22d84a38b6bcead76836dbdd76cd8bb42bb96fc0dbc04ad9416a6965a1ea2ba75bf"
            }],
            "kernels": [{
                "features": "Plain",
                "fee": "7000000",
                "lock_height": "0",
                "excess": "089117c0b4b563b22e1df97a5be68396f9df5ca442adb28855c7007a161fb753cf",
                "excess_sig": "c41b0e1b85bdfda5cd24867322084146b15bf9109d2e6d37205a1aa6924c1bd71b6017b2e867d4937274f160f45fa7529dbc5d07099da2e49ba20230ea98a3b3"
            }]
        }
    },
    "amount": "1000000000",
    "fee": "7000000",
    "height": "274618",
    "lock_height": "0",
    "ttl_cutoff_height": "0",
    "participant_data": [{
        "id": "0",
        "public_blind_excess": "0327da1ffc6cd52c4a74761dcf416f6d392106e5d0894aa2ed7a7dc80ce6ec3025",
        "public_nonce": "02349356c5c320b8061daee5e9010feef6eade9ea254215db50e09caee89be7ed0",
        "part_sig": "d07ebe89eeca090eb55d2154a29edeeaf6ee0f01e9e5ae1d06b820c3c55693342f02bb1e408a34a07f027e9c858c40ac13183a24145bb78a52cadfa839ee90b8",
        "message": null,
        "message_sig": null
    }, {
        "id": "1",
        "public_blind_excess": "0346b381f84a1fa71757a6c61d9e0261297348272e07d771da6bf14b338dcbfd85",
        "public_nonce": "02f9593c91da7673a8d6a947633e2e777ff1485a445e9d9030935badcc08294f72",
        "part_sig": "724f2908ccad5b9330909d5e445a48f17f772e3e6347a9d6a87376da913c59f92d9f9263353c72b32e12bc7355b0156188a423e3f441eb5949d82287b0aa12fb",
        "message": null,
        "message_sig": null
    }],
    "payment_proof": null
}`)
