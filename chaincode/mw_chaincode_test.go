package main

import (
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"testing"
)

func TestInit(t *testing.T) {
	cc := new(MWChaincode)
	stub := shim.NewMockStub("chaincode", cc)
	res := stub.MockInit("1", [][]byte{[]byte("init")})
	log.Print(res)
	assert.EqualValues(t, shim.OK, res.Status)
}

func TestValidate(t *testing.T) {
	cc := new(MWChaincode)
	stub := shim.NewMockStub("chaincode", cc)
	res := stub.MockInvoke("1", [][]byte{[]byte("validate"), getTxBytes()})
	log.Print(res)
	assert.EqualValues(t, shim.OK, res.Status)
}

func TestIssue(t *testing.T) {
	cc := new(MWChaincode)
	stub := shim.NewMockStub("chaincode", cc)
	res := stub.MockInvoke("1", [][]byte{[]byte("issue"), getIssueBytes()})
	log.Print(res)
	assert.EqualValues(t, shim.OK, res.Status)
}

func TestQuery(t *testing.T) {
	cc := new(MWChaincode)
	stub := shim.NewMockStub("chaincode", cc)
	res := stub.MockInvoke("1", [][]byte{[]byte("query"), nil})
	log.Print(res)
	assert.EqualValues(t, http.StatusNotFound, res.Status)
}

func getTxBytes() []byte {
	bytes := []byte(`{
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
	}`)

	return bytes
}

func getIssueBytes() []byte {
	bytes := []byte(`{
  "output": {
    "features": "Coinbase",
    "commit": "0828419ca690f41a5ef9622f715a803b39dc0690d5eb8f0e4be73bbebd2abb5786",
    "proof": "74ab8b873543c05e6f7e88b27a7c7e8191a4030570875f2944089ba0e5bb04f611cb0ae55d2cc23c10234f354bb5f9563b53c8adab00f73d06e2e186503bb2890c120bf0662db341b5ac0072acbb3e059d9bace9baa304233916fe710c8476988548714fdf5224e3ab6de05c1869af40f57d533aba451d202bc0806ca9c4817a6a9a8226485cf18ecb392f68c632a3f147a9fedba00f1592501b51f18069dffc432901c09f508f6829382dbf643b556afa9f8b52e1c955a5f0dabc29e725454f06346d6dccb15a18b857370b6ac43551f19c3377059461d3074d3450edc5c713040a8ea3334bd1663f6b03a85c2c0489f7d8d7d590562149031c811a3061d9a969e1ebfbb4122d6cd2f8a23c31ff985989269947e5f58de63c7bc9746a810e7d144bfb39edfd22ad93769a04f58205e74b644d1f56dd794b19a846a2cb5fed8993b1204865385d6eee148dbab6a1df4d4bbac63d772806fc531a4987712aa0de64e401ea4e45e16c48019a7f1de7925fdbce5df4518c9339c5cdb47a02c737de9249bf6dea487f7d924148f99adad1cc8c0d9a4469c21d5032718d43afb4e6a6d82bfde5ef6ec281fdd6a72ad991e40254045c6b7117b5831fc673b4d4e4b94eed2b6be2496f7225ab7124e0ef0e5670997a1261313c313eded9ded78fd494189b738812e02942ed5a6fa674064c6a0521edfad52b884b5659ccafa71e1016116c695d70d2a87c40e935003e4e0f93179f912801b64f04abceb8e4601e54eba5ab86a59fab61251cf5eae8541c90182a801ed9a0c4da99f0a2347d95c1fd2ca4f2766ebe49868534a0d5dd578759421d7923736160c7b836872c4e3cde15d8688f545440fcf654dd7d23cef863e9d8a796caf04dcebb9c0de3e8285a6b5cdffb45a28166d4a8a8a86969dc5231ca92b76db0b9da9d185cbb4d21e0782973ed30e1e871"
  },
  "asset": "¤"
}`)

	return bytes
}
