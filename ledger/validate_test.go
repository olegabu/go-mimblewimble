package ledger

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"testing"

	"github.com/blockcypher/libgrin/libwallet"
	"github.com/stretchr/testify/assert"
)

func TestValidateData(t *testing.T) {
    for _, data := range testData {
        bytes := []byte(data)
        testValidateData(t, bytes)
    }
}

func testValidateData(t *testing.T, bytes []byte) {
    var tx *Transaction
    err := json.Unmarshal(bytes, &tx)
    assert.NoError(t, err)

    err = ValidateTransaction(tx)
    assert.NoError(t, err)
}

func readFile(filename string) []byte {
    bytes, err := ioutil.ReadFile(filename)
    if err != nil {
        log.Panicf("cannot open json file with test transaction %s", filename)
    }
    return bytes
}

func getTx(slateBytes []byte) (tx *Transaction, err error) {
    var slate libwallet.Slate

    err = json.Unmarshal(slateBytes, &slate)
    if err != nil {
        return
    }

    ltx := Transaction{slate.Transaction, slate.ID}

    return &ltx, nil
}

func TestIssue(t *testing.T) {
    bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "092e6fdf366508bcbab6a336639f8046fe8b26ea58858035ab1110199d355e85ab",
		"proof": "6de4e50fcfdaa8013313145413df2b72ba9067dd77148533f52d3bbcffd7b64d5107eb494281b86fa568c92e91a9c9b787d5ff58603ac47af84b3ef8b56c8d54063f16aa44eef14dd3225e90dfffdab80f9a669c28b97c060a545a140900ea801a18746ea5c20756129b6437719d409a24a0f2d3a7a027b231567bcb914fbee06e9ed85477b1fe6a2febec76e86b5b4873f2f8e782538f4be61e6f1683571c41176d5e63a287a14bd05ccaae727d32130d7cda80b191d86f1d173979efd67c0357dbe81dfe9595eee143d1ef82519c47ca2883fe02132ea149e402d17d070e72badf2bea4f79acda686db213911f2fba835d7ff8d3a60cd459c8c74e87a23a83f9e78b28da57553a22aa4bbe822689d8dbd10b2369c833d75cbdd1dec359e60fffbab5610019649a4f107b26fb6139be230663c87aa3fb092c86bcd832cf8131b25285f453a9f285baefd078795203667d32caf27af0922dde775e6e60f404041d49032f989cc62f5b78257b641ccdb796077c43e29761b79e60a626bbaf0ba14a8b2451a9a9dfa92494cf810e9047e0852bd911a5cb42a9a0513db69308ad58c323b6c1d33b79e0f8a1cb6a574cd58c9d0691c8825b46592fc418c2ffc5f7380f5d3a5f8698d1b5073a8d2a0b75e10e9860977b841d8877f254a9561a70b4230388bc54a648398e52a6e7b5efd5a334c0c18f71d762bf833fb6237cf2cc588ac09075e772e6c803096bfb121abc116dc48231decc07bf0599732fed20033182c78b691dd8c96f5ea2dfae225ccc916f4792a6de96f364ce42eac13fb5e9a083b38194a9aa84a16f2d2445546c7779a412d4553d8f69411f6e30a8232d2b8bc3bf1aa63e2fd1bc28b3ad2c9e8710e1fc884edd42a3b0673392c0cd6801869ccb54dd1a6cb2d0d61bfaa96876ee71f5c735879f9b0122e10f1a260f8bb0c892b129a2d5"
	  },
	  "asset": "¤"
	}`)

    ledgerIssue, err := ValidateIssueBytes(bytes)
    assert.NoError(t, err)
    assert.NotNil(t, ledgerIssue)
}

func TestIssueInvalidBulletProof(t *testing.T) {
    bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "092e6fdf366508bcbab6a336639f8046fe8b26ea58858035ab1110199d355e85ab",
		"proof": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
	  },
	  "asset": "¤"
	}`)

    ledgerIssue, err := ValidateIssueBytes(bytes)
    assert.Error(t, err)
    assert.NotNil(t, ledgerIssue)
}

func TestIssueInvalidCommit(t *testing.T) {
    bytes := []byte(`{
	  "output": {
		"features": "Coinbase",
		"commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
		"proof": "6de4e50fcfdaa8013313145413df2b72ba9067dd77148533f52d3bbcffd7b64d5107eb494281b86fa568c92e91a9c9b787d5ff58603ac47af84b3ef8b56c8d54063f16aa44eef14dd3225e90dfffdab80f9a669c28b97c060a545a140900ea801a18746ea5c20756129b6437719d409a24a0f2d3a7a027b231567bcb914fbee06e9ed85477b1fe6a2febec76e86b5b4873f2f8e782538f4be61e6f1683571c41176d5e63a287a14bd05ccaae727d32130d7cda80b191d86f1d173979efd67c0357dbe81dfe9595eee143d1ef82519c47ca2883fe02132ea149e402d17d070e72badf2bea4f79acda686db213911f2fba835d7ff8d3a60cd459c8c74e87a23a83f9e78b28da57553a22aa4bbe822689d8dbd10b2369c833d75cbdd1dec359e60fffbab5610019649a4f107b26fb6139be230663c87aa3fb092c86bcd832cf8131b25285f453a9f285baefd078795203667d32caf27af0922dde775e6e60f404041d49032f989cc62f5b78257b641ccdb796077c43e29761b79e60a626bbaf0ba14a8b2451a9a9dfa92494cf810e9047e0852bd911a5cb42a9a0513db69308ad58c323b6c1d33b79e0f8a1cb6a574cd58c9d0691c8825b46592fc418c2ffc5f7380f5d3a5f8698d1b5073a8d2a0b75e10e9860977b841d8877f254a9561a70b4230388bc54a648398e52a6e7b5efd5a334c0c18f71d762bf833fb6237cf2cc588ac09075e772e6c803096bfb121abc116dc48231decc07bf0599732fed20033182c78b691dd8c96f5ea2dfae225ccc916f4792a6de96f364ce42eac13fb5e9a083b38194a9aa84a16f2d2445546c7779a412d4553d8f69411f6e30a8232d2b8bc3bf1aa63e2fd1bc28b3ad2c9e8710e1fc884edd42a3b0673392c0cd6801869ccb54dd1a6cb2d0d61bfaa96876ee71f5c735879f9b0122e10f1a260f8bb0c892b129a2d5"
	  },
	  "asset": "¤"
	}`)

    ledgerIssue, err := ValidateIssueBytes(bytes)
    assert.Error(t, err)
    assert.NotNil(t, ledgerIssue)
}

var testData []string = []string{
    /* 1g_rep.json */
    `{
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
				"fee": 7000000,
				"excess": "089117c0b4b563b22e1df97a5be68396f9df5ca442adb28855c7007a161fb753cf",
				"excess_sig": "c41b0e1b85bdfda5cd24867322084146b15bf9109d2e6d37205a1aa6924c1bd71b6017b2e867d4937274f160f45fa7529dbc5d07099da2e49ba20230ea98a3b3"
			}]
		}
	}`,
    /* 10_grin_repost.json */
    `{
	  "offset": "2f9ff6c511e4f0b5674a4080f1ed3e841d7df15e2ead671988a53c123540ec64",
	  "body": {
		"inputs": [
		  {
			"features": "Coinbase",
			"commit": "08b2a32e432b2f0fddf50ee2a8ccb16e402a4065a88de147d12f198f312a19d46d"
		  },
		  {
			"features": "Coinbase",
			"commit": "0855b1b9dbf4f8faa77cef517fbb9187c846ab31e9d408fa619668fe67cc23dbed"
		  },
		  {
			"features": "Coinbase",
			"commit": "08e38a8930a050109405393284e06ec0e2f0274caa17344e2354145876a0309ab1"
		  },
		  {
			"features": "Coinbase",
			"commit": "08451f7c868fe34a051e51618ad567e8388e788c1421ef8a0e758d37fd678d4e0b"
		  },
		  {
			"features": "Coinbase",
			"commit": "094fc4f820acfac34e2684ea0db4c6f276631750865e669e578fc88e33a5d90a4d"
		  },
		  {
			"features": "Coinbase",
			"commit": "08919bb5b74bcd0fb054acc60232f8483dc1c9645c57265817ea4b0fd5d6d034d7"
		  },
		  {
			"features": "Coinbase",
			"commit": "086645ea2c239eeb5ab290f72ad5845cb95357597e55baf817ae26875beb05e5e4"
		  },
		  {
			"features": "Coinbase",
			"commit": "09a8a2d3cd58c03bcd48b8216d0363ddbc8b146a3ace609b32e4ac5c4dd180fbec"
		  },
		  {
			"features": "Coinbase",
			"commit": "09ffe819185c234d7e3950a498ffd41a3149b8455306f43fbe8cde61710551f34f"
		  },
		  {
			"features": "Coinbase",
			"commit": "08c22f6f1200acaf3c38e8aa6a9aa8404eb54bdac25ffa31b9b565b01c6462434c"
		  },
		  {
			"features": "Coinbase",
			"commit": "0862b5e77084d5b0705fb9ac25797b55fa93f0b34e70b5b786296e3ea2e0413f53"
		  },
		  {
			"features": "Coinbase",
			"commit": "08aec8394e2cf47f9fdcda006d2685d60308fab44e4a9d8287300b392d90d353f6"
		  }
		],
		"outputs": [
		  {
			"features": "Plain",
			"commit": "091c2dd4cb7bec56ed314f55ec615ce28784ba39de05bcfbb3cbd5c39fd8d508be",
			"proof": "07fa91226ac7cba89af669230d5e61b6985ff89b3d5d0aff6bf266ad603f656853cc8cb77161db604349afdc37e7038d9634a033d33d1e8020530fa53dc6e33b012903e50967bf59c97cb68095d6d6ff23305214de91830f9781303d6c35dd7a782a87ba537d33ae7804848bed888ec24467c088ba899eb7da2de40178e04720ce71a0ec19cd9ab76e282a70142bbc48efd9fccb454d9fff345684d1a9d03aebd732c197528342d09e62d9a271e2abab4e097e12b8e4543dffd00abde78b999b4cd06ee508f9f235fbbab0bfb8a49f85308d37e8aae38382831a2f426900bb4875881827eed7f0bfb501b127fb9be1cec8387bdefa900a28e5de4e08616c590d49e4e5f48ec001026a80b9331a0f5a4c1508f32119cbc2af8b46817e8b03ee4159496be1c6315d5b53286f3dbfe70d819d26f57879ece7cb56682d20e00513f98e00426403d57065427c659be230eb4a0b0e21f1712a052828e2f775a87bd92962b6014a7138c363d899ef0ac8b6460e97e9a0592a2a0bdedb3c6ef09da364f908d2fd90893c3a218ebc5a0d39fda8f1b35693c3205fe8a5587a80bfce754e001957b7f17d72e4a866697f9488947eab680e4ac9935f9628e51f97373feab7bbc08ab3f6c6e0cd6955eec42e81a840c49502ca27580e04bcc5cd50b75ec9a13d8d42978ce80cd46ab73090291af58814334d29ec42c3073e30f0b6a73e618fc6793dc00f277a807082a8efb383f5765fdabbf18c035a792a51b208e508ac5d720d59c651555ab46d13d8d1bdf1d3faca6c2948088bf4ec138462cd7daac35719b7f44fac734d93abfcf74e09b636122c04d3424354dc84d508ff7d3f15f41bfdba5b2a311396b5c97a2b85ecea6991f4c273a20b03e4f11915b563b4e2589354503d5b050a7aff6d679a6f0864a135a3075fc9f6ef90aaedf8fed58943bc2c86fa686c"
		  },
		  {
			"features": "Plain",
			"commit": "09d5a69302608e25aaf0ad354d83f5a2311532976b53ca30065626710c3ef176d1",
			"proof": "47028f67ed9bb82dd43693827aff451bf263138d8440e6a5443c4cb1d29d2398ae3addaa092a75abae8477033cd77393bd40467c4037821b469583d8db2798ec0410dd8fe2af14565e21fc735550abac94f0fc87e483065671169b56029a92abf3393d74969ed28f17db18623faffb74c33cc5507b3762694431883563e8fd3442cbeb58f4766b749733686168ef8a0bf32831c028218dc5a046145c1f0241c5711e6f7103e4e08dffc66fc9285079e0e0c8c30eb963f9e81a2eda0bc87c573b1e6bfdd0e965b1be68f553ca5443cf3e19221a239c5bd36690efaf882e35493146cd1617fffc87c2c9b5575ced1c238fd88c8624958713be3f66a46ba83a9c672729a16008e4045dc276e1b14a707815ad65bc10e4197719d21d6d8a9602839f63882a0dc6b4b7e02a9b1cc7ef53d3f14defde535aa6b97001e979c65f3d2a3441e6e7557a90d65db3d863b1b4c55c41e467b16977da091fa70ab79ed9ae78c350a400b3980463308ee3e786c30d800236df8fb453a804ebcd575d1dbb576109ea54ae4e8ed95ff99f3a0e349f7c09588f55b373855f2c8ed32cda6f680bf4deb472affdd221d06788d1f0e6b76021a4cef7d7672f7c5e75407278b66b152fc8c08580345cb62f1054b54770259501861b644c134caefc6c2b70c067248e204b971e8c7343ce9770f0cfe2af318420c16a451732fc035eab75ff2e121816fe9f18be160dc8ef862cb525593712f716a66caca8398a6bf6f30fd6a013859abc3d04a7b50dc2c1b63212448884f99f2887ed11e9bb4ecf863804c60e8252ae90f2a555db9049e047e9ac6fec2501024bf5a44a0d367d5e2e56f755b87ada84c88370d293f5724096c1e8d79d564b5657854d08241e3d174f0baecaf5ccbdf5ca1b1f7462c410b5e8b5c4b4fa38ad548b7b101e97e35aa4bb13a03da2c72deff0316ff68f"
		  }
		],
		"kernels": [
		  {
			"features": "Plain",
			"fee": "1000000",
			"lock_height": "0",
			"excess": "093593d12cfa0527b2715a95d82eae0581b79206d0816c31a80fb6374ca5d977c4",
			"excess_sig": "1a5edacee4391c63993b6835be5ee076e137a463ed5144302f5ef9f296c096c84f7af4597b2b1096ee55913c7fdfaaca18ff1d8c76f9242417fab92d3ba084b6"
		  }
		]
	  }
	}`,
    /* 200_repost.json */
    `{
	  "offset": "10d01d4b60a57c63fb838545a541018b8c40b9e6387f9e735116a03600a0dd6c",
	  "body": {
		"inputs": [
		  {
			"features": "Coinbase",
			"commit": "0986958451aca0412fbaaa291dce94cfe700eeed4194a5b759ccd0406cb926cfaf"
		  },
		  {
			"features": "Coinbase",
			"commit": "0883114755974ea9006ca4ecc2697e89b356670f79601b8d9b24ab79bf87e6da2d"
		  }
		],
		"outputs": [
		  {
			"features": "Plain",
			"commit": "086d88c2d5a92f8afe3362f0e3f1f4cf9b6fdc8973bc3b8b99882461cdde572ed5",
			"proof": "d979580e875c650b536cb0b6034413828e94334184f55c8beae2cbd36f1e36a915a1f1571622ea9907ab6284b83cb013420040cd677c76416b5b19e8ebf041ad0d37966d143bcae23737534c87229034ca323d20d5dc24580f4c2eb49cecb33270591d0db765f2f36d655289a8baee16e8f661e99be56502a1484083e690215ca080a6995216372ace5b861443913bbc1d3c3813ba5df6f38e5965cdf0cde1d0797cab2a9f6559a0cb96512646caf1f3caf5a8fab80f06e5b879b83ea96bf2af1732b929aa672d8b996f0ef35bdf107a11166910eb79208fad6545412b8c922213a10d94c1c3780dc9ca59d9230ad6ebb96ed2649bcc57965d506822809919ef80b1b8fd5c233f5433cb8a61a50880b8678e372820043920c547a686f9abf709a10f8279338a2efafe2d0c2039fcaaa2cef083d67cae0ce7b6883ff5d4a1e63dce5baecc42b7ccbaac0fbf20a7dce71ffa47c93dbca618524b4ff8677a44f13969d80080aab15c1f5be8a7986a837edab4b9688204952549cee6e794e70542665ac4976e7685ff1282868866d87188fe757a010de68d256767e3b502b5c26e2eaef80eeb153ea0f302114fafbdfd3ee32ab013a661a3d31f29db237522523030c33393e99aaab81e7525e2d189d1ba5c2fdcedb6c76fead22fd6977e63a768ef7dd3524528d703dfc0907e5831eb948291103c1e957fdf6d64b6f44ea29a04d1dda34fbc0744294d1627e94af071fea9dce595b3aaef24a9ef3aa1a63202804a5262b9053c23b0927311d5bdff64ea0105e12e6cf112be1f48c01ee463e70e28ae452f576701bae331cbe1e75432fe0960c90ef1a7ee72b92b6750bab933ce1a13542f59143f35546edc63ba69ce6a04a885a237bffdd6dba50a2868d1f21eb8987e7e4c79929c0ea982a2350866f91e5b247f20eb82682e6601d8e2310607d8da3fd2"
		  },
		  {
			"features": "Plain",
			"commit": "0807cf22056682a8852011f6af9752881a7bf8606e13a2ed4f92ac79ac76857217",
			"proof": "5655d60b6fd5e0a14a385adca49cb77a82212e8e1fa063d784d415494f2e2a11337870e3eee4ec84fbf3dfa13c64d7eab8a3953baabe3124fd904b0aed7347230fb0a4a40c3d12b546bf1ff6fee06912cee53e530643a148e6b63a9990dc3216c78774ebb426f9ca94375f5d8232e102393e63c25d58dee7ece80ec47d79528e6ade42829645e22387bcd905dca2386c9857db7fef8b6f0f0fc9c26dc3b1e0807067723b64916d24b1fb44fb1edab3f782f07960b1fa06c9b3dfd82f5922b5876916990e67ba93974e75d4a0bcb9e7f774bacf9ec3e78f3224db2657856cce0d10276d6f84c90fc4a2a2079203445eb2f7159294778c5d6ae2a0b8bfc0717fd41cf98a9d26baeb2d5e006800089f7d35c5a5ae1a97c6543ce708b445ff47fdaa7c76d2eb00a07ac4e66ab7b3d4cedd2aeed012fdfdff54fb25bafb1599c96e97f9783c4915ea02514145f94467b2967bafe071d22b6c0bfaae0870d94f14721b793403b51fd30cd74c0e1e21f66b8fdc777384f309f133c38cd7e4d404cc0822d3d9060e0eceaf3b54405989f033a1b965623a2e5ac967f3719722924274979270944c1ae853a5eeab0b3503d840f72423d86cd3f142844d14b3fa376dc0758bf9aa3d2edb2daa5401dbca300e934af2707e4e4f1cb094b422979a44c3f8c5a8055c2ca038ef795c3af83d43987d4214d7073c3fe6a1bfc39f54682868cd917cf50158f0e0e3475296146b017b40e1b76d866a7a5478f2a6a0a0c88a32e3bea8903a0b0f8b6581ad82a34da37952e97399749bd9f88757874166221a23e54e9d83cccb18b86be0d8adb0113e6a5289acac10941599a1462bd201dece90be8df63a93cd3a532f1d1addc9b449c7db07c88511ea6920c02efb5735f12d99b289a7b4cbdc5690f4ae945a4d0015c33bc6958c9d4433fd809f10e09f7f6f36cc03df335b39"
		  }
		],
		"kernels": [
		  {
			"features": "Plain",
			"fee": "0",
			"lock_height": "0",
			"excess": "09f6c1bc276bbd629e3f2b8d0b7fe513a39fba2d85b5ec1b8e080efe447e12e502",
			"excess_sig": "13b579401940605c6137e434a10c7048722b495c5b9f59f5c1771379c5ff93986c2a6eeea26f3e45b4a05f495c26058b9d0d6ed449d71c57569f675ecf7e6bbe"
		  }
		]
	  },
	  "id": "e9d41cc3-0397-4913-9bac-f8b6b1c9f271"
	}`,
}
