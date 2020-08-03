package ledger

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTransaction(t *testing.T) {
	bytes := []byte(`
{
  "offset":"b6e91f83219b017fcba5e9b3468581f6eaee3204d8c791c5f9bb8e77ee4c581a",
  "body":{
    "inputs":[
      {
        "features":"Coinbase",
        "commit":"09a55256283c7e470c64a989aaed2542b11bc9cbe5bc581b7d2851638c5f82c6d8",
        "asset_commit":""
      }
    ],
    "outputs":[
      {
        "features":"Plain",
        "commit":"08870310a04a20c49484d10d6ef91b5f7d9dc3b22394ce612f8d0e0b91a3d7d7f7",
        "proof":"d3b90aabb339cdd8b1ce13af437e88c82c9e3fe79690065a637023543723045bc0705a91015ca7433db82a6ac45b14b01fa3d8bb9482330e0566875b06715cbe0ace0cc39737b8bd4d7cc7a36ca0f5effe6f12b5dbf6908460f6f6191b37fa39d7ff06dc1ec6cf5a1f439f5ddc5bf72b334d7a0882fdadeadeae92cf6ac56f746a2c4e7b158951288e1ca5cc7b4c617bcdcd547d340af1b39d552d67b9c36fbfb1e7289dd617281d231b973f63b401325bd8c85ba240b8474b2b8bc8184af903e12892de1fd69618ae0864a12c0d50e0755d07fd02ec32b451319a0ef0040054ac35266036385c31ea1eb48d561ddcb00f5dad5cc8b423d0b1749161385c02a30ac1a37a8c16a14534fc0c8babbdb963bf8728147e6a2a58e226a0ddd9a3f57ed05c585ebfc20dd49700ea4499c5b87e227cc3fce34ea9398286a769471022998b9ff4b7980798f5979dec471db327efff1a39e172c213df76ffb043a8e59a342a300016c514ffd317accd10cd5ea3cd77df76ac0422cdac4c571658bb9bba8d33956f87d3a4c35b64380eb5c3c2d144cdf3f93b2e5c7aa7e3d16e1d39f7509d71a043df77d737108109925a27760e9580bc42d13ca4ea8c751faf91f1d090931545d3be18b536fbfe35fc5b51b3cd5c5edeb4593db36450b386c56a39542a7b7e222d5ddb9c3ef115cc5397922c3a95dbaa0b41bd028801919d2912fdcc40db52685a61dda13102fa25251363483cea0deee3a545f93561a5866625c7d97819d0f6114d162ae91938a3a51ec858bb16c93b11227a839e50feea84b1e2aa3539c914609d916a749d724420387f608990495c0fde9c41f2ea5ab7de7c5f43e90e138128e7b0d5fa8f0a6832ce57ba1481691cc20b205e25c15f729313a7045020d25a82b93ab0a633fb6ef3bfa23e13fb6ecef297bab4f0776e6500f7feb2e49eab9d58",
        "asset_commit":"0abaaa3a3eb9d3fb1a33822b0c05017078ea1144984c1b799fa09c9ffa7794c0a6",
        "surjection_proof":""
      },
      {
        "features":"Plain",
        "commit":"09b738f954132ff7e190f36daf4edbfd4faa5b96ea9f67bcc0fe53e41edda8611a",
        "proof":"efde34a99e062891834a20c72cbf45050aebaf218b3e41d6fa01d9c2d79ce8eca2d8287e0be052c4d4bca632345fc6f362a53c3a9f039465576dde97d83528cf0afc4189f43c4f3348aa04d48847fa7dd5395772c3c94d0592a3e079fe17617d9db0f9d39c57deec3ad84443ca493df6eebc9efa8666e8a129237ca08ab4a922c9ba96919a3cc5af3740da267fa4c6d35665f6f09497c935fc88d65dfae2117bb9588136e692b64dc3c4429a46c96df1ae9e2c473a05851a121fba218e07a9fd5e3c638dec0a58445d2508881b0ca950b672f919db9ae08648f2fc5882b576d1c473c7fa48a46a5b37da4e0e12470075baa18f5cc171ec96ab818d91bc4a001d0f10ab93cd2ceb6327504f12677637019c610751361ad718b9b3b3d62ce7b4fd9235ebe9dbb7ae8b1f3b45b84b8d624752cb373c1358176a2fe1fa20fffd31b603200ddbd507483cce7fdd40bde9847dd1fcc80143e4e9095575b8779a09e713ec2e02d68821c317318907494e362abcbb4f3850166d18b3a1f633e26d97919619d2d24e5081f1433d6700ffa6145d224b161b1ea7599d933616c5377e5452945520d94ec13ca2aae8bf92e9036c76ac81d3d31988accbfbdb3f4f28de05a22079b40530e1c61ea92bbeb7eca821048065c44bf9c5a6c8edc39a211495985978cf896b24c22864862f489af89ea4ad183335e5049c8bf708e4c09ce6ddd1e089c825137c247b2939c8f0403e99858fddff3ab41311122cd32206583a56ad696ae033ae3a63ecce36502fe6f62c93cb3f011bed777dc7c8ee1eb1873d50175aa2942f3e539eab4813c7c461a3aa2c452f6846c278f059a4d8b7b877e63a547b1759f84b698b85833032e5d156f5e8da3def89257ea627b47a8a2e466af583094baa602bd3ccb2f4dda7dd93acc0fdea2a38216b229995bbd7128ae26f84b40469021568",
        "asset_commit":"0a92573f4ae8469db6d43abe95285439dbfc16204bf56ee23cd0d6705422f52be9",
        "surjection_proof":""
      }
    ],
    "kernels":[
      {
        "features":"Plain",
        "fee":"0",
        "lock_height":"0",
        "excess":"082f01f54ae3a1bf345abc3e0e001e60ae6c473c50e7ad7005851b9e86a790dd94",
        "excess_sig":"023286e7c348516814e3d675e72d90eb93fbbce8dd513fe5abe22b4faf843970d0fb84ec0762cc9a642167b5f4c4c88dab92607b894659d2f71a62300f9e05d0"
      }
    ]
  },
  "id":"32e2740b-2363-4c70-8ad3-bb404fb40498"
}
`)

	var tx *Transaction
	err := json.Unmarshal(bytes, &tx)
	assert.NoError(t, err)

	err = ValidateTransaction(tx)
	assert.NoError(t, err)
}

func TestIssue(t *testing.T) {
	bytes := []byte(`
{
  "output":{
    "features":"Coinbase",
    "commit":"09a55256283c7e470c64a989aaed2542b11bc9cbe5bc581b7d2851638c5f82c6d8",
    "proof":"d359b542447268e71d7bc0ed5bbb9fed0f89db4f247c29c4c0e3189c6b4d8d944d53044b8b4101eda13534b90e867f61d7ce0a6fffbf1aaff68fdfa62e7487e5037828048e55e0e5a8226b1cc756c6f2347023460e6028023c1441ff7fb02ce013ba95b45a50e8f46e85e8286fb02e1aa3b00729676e5df976322c782ce8832bf89c29c2daaaefe02222d10f661d27b716853e1d2faa4c946787e9e98ccf3b1b4fd16dd843370571cd4170057c6a9a4be106ff9802ebe0fad01bc55b4e869347886d9aa3336a0e6bc41ea065ebe0d89da70242ed96774069c5abc0c7c65bdf8e1b3edf773f4fc8448eb60febb3645c7f5c3822b6f9baee022869773d2509cb2005088e6fa75250d57948430ab04028cc418cf76e2821180b2c28e38e8dbc0bfcb1362393fc388343475951ffdd6ec0112eb2bf8b5735bdd23c769fd01b93abdc831270d6ad3f7bfe64a9f07a72b5f524b9f4a737f0de640bf6c21d4baf2b9c0d0304028d3e4936446466d9b96a814248cea58e811f5f4a0f2c2d9f6bd4a91d461f80bc6033d19c678885a83653d2fbb5b781f38db70aa88712ba3c95c88bcd5d9c8da1b1e902fd89bcc1ed6b85c681c6418bd7e6f45086c5fcb3701fc0de844b2148feb8ca84889b512275fe80c9aec59d3082b69e2e3589a6ccc77cfcb3dc86f56b234df50950ab9264884117243372e66ab56aca1872ff22fcf7a4c81555d320e8698e3a5417fa88a60ccac698d0f685852f0421173bde8bd139c5904e61b7bc3db7f85fd0293b1a1c74d48b2069cfacec74bf3fd1bf7bd2c3f688dfca9e95a23f4eedf7a777e12b1b1b49dc63f98b3e58e289b34d5ee4b55868e40a5ff27ce0393c5213e575fd7093f86d127a679adb05980cba0ed679f0f4406dc23bb54163a3efd6dfe77ad27617e178e7041283cd605e80966bfa6ddb7fb0ac089eb8cf1675b9",
    "asset_commit":"0b491c9639db5d37d4fe39f09c0b482ce9fe384171a2342da5a75bc3693becbd66",
    "surjection_proof":""
  },
  "value":3,
  "asset":"¤",
  "kernel":{
    "features":"Coinbase",
    "fee":"0",
    "lock_height":"0",
    "excess":"08c63f8b6ff523b445c793af439845b232a5142451778f31ba9174a0174f6f062b",
    "excess_sig":""
  }
}
`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.NoError(t, err)
	assert.NotNil(t, ledgerIssue)
}

func TestIssueInvalidBulletProof(t *testing.T) {
	bytes := []byte(`{
  "output": {
    "features": "Coinbase",
    "commit": "0980596ec61a13a445d49ab6b9a14bbe29d88827a723aeeac12d1ee0b3ed4a1882",
    "proof": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
	"asset_commit":"0b491c9639db5d37d4fe39f09c0b482ce9fe384171a2342da5a75bc3693becbd66"
  },
  "value": 1,
  "asset": "¤",
  "kernel": {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "08764a0c0d67bc674b958d756642aa5ba2b2371d4eae6bea22debe9a2ea62844e6",
    "excess_sig": ""
  }
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
    "proof": "086b8dcf66ddfbcaa93513e795c1e2882a75d614d78312252a5cbd83fb436e563b35cc2615c7905857b58e604529f3f76b4dc1e56b2658fa82d79e6f4a961e26038a6987f949d7982e732ec4f53762a6c83dc1feb3b41839386d30d6776907938af7dbf52c0f0f54979f877735eff39a07e3463e201be8c8cf35849ad744e1d2bb7417ca9e5836e3bf36d94258ba03bd7a478fd18fa6ee7820f11e5c43c23b2d18d217307b09a05441a6daa75aaf185781f73532b73afe7a332d14938d84021ef5a6aedec66042ea5ee8350164877a50c93307c9d9b1aae7975cffd65d79d48ae4bd9a1105dfe9b19b3754dbfc63a8081dc22d78b5b9153f041001c83b95a65d141205b045e44b9308e2120ebbf9a11b29c335c57046c514c969fd13dab9a791d9e6292ae1c3f4c52afc5a3f5c7b2d077479047a52631388f34bc6bac65f2bfa95a7823e5e53fc4f514eaeb1020d15619267ec05349fa7c03706fc26604b913c6efe02725a98a32f477213b8855693552b313305e5cce1aad3ec2e63d594320597666eae21d51649b97e501a3062c8fd152e087fc2d59a2a583b7d9c6e7ed7ef4eab5e08e7b956c41653471ae5f2baf19c1f0107312e0e7d4c4a5e7e48ab293f2f860a484c913414f4ffe4d06626a515b2460a17cb3c19c6bd6d81b8d31664fccc342649399001387f3997ef8614eee5e7f45ee159e8eafe5256f132d94adca2ee99b46afc950792687b8812b2628d37679dc09782962694ec91d692b8414493c8f432983d7070baaa48d937a96ef750d8ba0654be7bb5e46c1bd0e2c622ec97f8cefe382acdd920af52f9ce53f375b5c4a0334cdfbfb948610fa1c435b3abccfb23f614db476723a6e78512c1ea459bb82869d92d4407f8f8561675fb1af571286f849b524d9874dfb366154d164f7089c33cd7c253fc8dd43ae68f407cb0730cac6a",
	"asset_commit":"0b491c9639db5d37d4fe39f09c0b482ce9fe384171a2342da5a75bc3693becbd66"
  },
  "value": 1,
  "asset": "¤",
  "kernel": {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "08764a0c0d67bc674b958d756642aa5ba2b2371d4eae6bea22debe9a2ea62844e6",
    "excess_sig": ""
  }
}`)

	ledgerIssue, err := ValidateIssueBytes(bytes)
	assert.Error(t, err)
	assert.NotNil(t, ledgerIssue)
}

func TestValidateState(t *testing.T) {
	outputBytes := []byte(`
[{"features":"Plain","commit":"08585fc9badfb18e46ffb53f4600a7d9872441c743df69f421531c79d0f6710d6e","proof":"1837320810e4c46f7e885a0ab8f21ba22799cedf5bfeb03db620deb3ee3861a9af4b2cc19c8d1bc8cd05fae22a92381f3d2a6c184a51b5f7b8fe4867d58f1bae08271fd26bf7897d57796a32c278692fb9dc7ab075a8cca69dc63202b8815ef421e2c395e8bef137aea904e6b963ce9d95565c6c20f61483b0a4466a14bbaf4f88063828e9486d5fab261e33e079e0af225b3a72349ae469f78eadb32829454ed51cccb4a5e7f95bc6333201565d0aba32756b386005aaf9a63757e459418b4ac14477daa1ba9b37fccd67030b809d007b4c76c636dfbbaa434e6854e127ee3f3b3a4551dd28e79423673df0310847246d470a0dd91a607eedf23e83212c76cfe8604ea7e19eaf5e95de0e6112f7f01b682b139402ffa825eb9e2c89356e40259c067f9ee90ea208f5466cce704270a9ec1459d200b37d8e05db020e605a0e13824aa0bd4ba31afc77364a289a849ae302c6a4fb37daa0d94607f141a6aae871469e023691b139e675ee85a0e986ef33aa507e9b1fdcd3926dea663a98096e200c92f87d744e37eb5e104aaf9167c403a652c65404aeb55ae3aa350b00f15335ba39350d87849179fc666dfc6cfda00473eb7e8c9bada3108c8894e527e5369c44efbb341c794011704c6eaa89eec0cdfbfecc8e10af3c7b541c0f71ddf54ce6cdc2512b676f94a347fb37c95df292bdc1dec1b1b251ac20f3ec2c8059e57e6419f48bf29c5e24c366bf3c29f27637a3d66d97ec9304635995cab9c1df5f5d31fdd8cc41996a17ebe8387d8ddcfeeff65ade8849fedf5dad5655fc3a99eccfc8443e6c37a29e520faae8f0eb4c471ba04e91f2abf1ecc6c5ce7f7c82e64a73c8a57fc88d012346882089e374641692d30027629a84ac389e481f6fa5654462b2e25f6dd6b38eb8fe960bcc013f141efb3b4a1798292735337c0d6980a4348debe8c817","asset_commit":"0a469f116c8b0df1ac3dca7759e7181e1dba4e199fe659cbd06aa1626a29abadc3","surjection_proof":""},{"features":"Plain","commit":"087b40e984177877a34e7d8f7d4cd2e0aecac3b880d2d2e8fdefb1979db7385ba7","proof":"8c5d70f07f6d40eee824f305465700b6a7c4274d72c78bad93166f9d64e994fa6918c6a573dd0e09c3dcb4401572face1f9c90d9b171568b245d5691a0c802ec0e29172ef1d65248a213adb3284f647c06ee3afc241513b92edfaf4a90df856f5a31616a851cfddc5f736fa5283edf9935971dcad3bb929f93c565e3b9a694a730d055a04ac29d419d1fbe8e1d4572fe7b175361156ee76d9b84dcc6e16798f52e0864937e8c816c8ad2df8a890ddab9aa85ee1897c10e8f4aa004d0e8b27706dc0664bfcc3ff50f1dda8b8d0296574594c8d6aaa67dfc4e1edbf5acdf2e34d5f2cde74bc7f3008b664e78f536939b20515aca15244f9ddd8e75ba2704a1792f26b69b6e353cdf8df2cecc91db45258ad7863ffb3e8a9aa8f39912756c98907921592658c53be1dbaea510f3d1658f84dd4df1c9baeb29e386f44c98b6a0624ab981773dce84c2bcd7e11a6226023869475ac9b64e4b650f5d4db9e5ab751310bfd80174d88eac4cf5fba1b3f1e3c7f72ae0e349e50567966cf526e2c772ea1b2ef51a7042815d1c50a447cf7abf2f988ae6678a3dedca752ffff069aba91f5842f69430c839153ab36a7172a13eeb1313868976b5161074dc30931ce6436cb80cad7771fa5502ae84f98cd0bf3bc72f4947de119120bcc9aecfc31d4bb1bbaa71feee1c1d2048bd00a7ada7521c20d7c0ca8cd6686cd84cc2f50b2349a20824607f8f9102637ce693ed833182a8a3d29cfab428fc427d6641e68bda76d27faba9183639a28e5ed3acd9a09900079be08e275e1212911d59561c710764ccedf1bebcac7177609ff2efebfc1a84793e4e56fd042419743809665af8b1d1d4ec2fd7756602a5698a550d0ba0ef7d2783a941f50a4b57e77a79195e510d64b13b11d7a19aa9cf37613ccb8703116448d85dc924d3821c33d0545004f7d137d28eedfd553d","asset_commit":"0b78fc196fd84d3bcb5b8aba40a3f0755a8cf40ae6b6a69cf2c952e58f827fb1fe","surjection_proof":""},{"features":"Plain","commit":"088e0650bf4f58f745b48a4a93807e1b748a049faa00cfe3315601dd883820c97a","proof":"b8d940ca0969cce6ada72b0ff08e2ec8e524cc869335a8675f5efaf7f23b9673798c6a128aea23fc1b87d921ffb983ab45690e4042787c3256496560ffa2723b0b3f7903c68bd2b8902c2b4d767cce4728e3c5b323e4f27972e6c8731312e288de3bb71799c2dd4127e51641210b55c40aba9cc59320675817a80747356602734294a6de1dbb987b8d4bce557f1a608b099b932efd60f42d8b1dbec211182fcfbbbb34a4ef3a67ea183e7f1f5f0774c45ae111d6a3bbe77f93b92bc54249380832d39aaec43c5034548c824d2e9fe21e597ca4df551687623b4e8407f1264dd9844c8243b08f1953419950dde87b57c855d85d1f0b904c15ab699a93fc725badfb6fb0aaa4109db0b76c27c09bd246965e8baa2498cbacdc9fdc72146e1ba8f27dbef9d6a1b6d232005cd494ac273c493d0678581ed8d2391cb73544334652c55f0d536ea2e6f312c3352ef56ca2a55ff63ef936f9f00474248efe01c37f53a7265a03961ced6a6dcffd9de902c821e8fee92421d7b44a517291e70b0f7ed6259c44b0153f06d7718236b6f9683408672d3299bb140ff3f713fd09fdf1a0139ebf46ef6355c7060a828e8cf07971211d4da304e2a2248e2e91c4d2a995d2a47b28897af94705b96c33cad38d95198e27eccd5974fc0532842128396790d18e4f99796a6467828c0a7ace4e3d9caf2585c1f3cda0fc3f7808b07d4efc5b1b4148814ece684a1272b4dfed3226922e1dc6a4a1bc63fd6df346db4d0b5eddf0b1b9143c834b32db61d28e1661a0980920470f75bc6c455fa487c7b19fa4deb97c48bc3f77a508eaa48cc9cecb1ab9eadf2a9cbd378a4d0c2c5244350f91f794d90f954f5e5b02c24751ef4a8f35b603d9c337085146d9caee59b7d8b9d84eb8f73e330a0d768f9663a44c7df3d785cc6706dde0d6164361d0521ddfcd1d7107694e9bc69f","asset_commit":"0a545a70b2130efd49a0f63b2f8213b3158e1df9cd579b5bb83ae317bebd7ee0be","surjection_proof":""},{"features":"Plain","commit":"08b2c1bc443ba0c4a7fce78e94d81b340a4f3426a58aacfdc65649a475c1852c5c","proof":"a5dc729372d35321faa5dcf122ec86d6997bba34601f541e4a0dcc93add076497f0d97bec15d624b6863fbcb72754b3da3fe4b2e446ce2f6ea175c58855e9a480aa55bcb53abacfb2a2d53b21c46f38b0543483c279360ca2bd1c11fe1bda7c442da852a9fb915999459dc4c9ca7d79e53f4ec35a0c9c81bde1e425199cd01638cbd0e954043c0ab75cd7669e11d4a6740e299b3f52c29dfd669bc58b1b74b0c7292ef237f4b73598165763faba32f5ea359920da16b939ec40cacf924ce44172f0c116c41f9e7e9ca639b190f64c37af1fa77fba1a5f414babbd725d35ce003465e4ab2eaaac219807e3f8daee685b072d2af5d27cb2d962d1475aed02a2b6303cb592bae8129f420d689bcaef49ec220cd8e080d11cfbc600adf260a03352a98af34e00e7b0b8fbb3f4bb21491da3b425eaeae37846af316d058f1b3d373d1acf735117306f7c58f1f46255c7779fbf6a406571af69a12d1b98704426a99ab8e06016ce33bc27a84407e732b46af7d4ed7b9ef505082e7b6e1b63160802b288a2aef0ae6f2c0399e33b17266bdfb0e39a3b5ea1524f513b62bfc57e4917cd70dc66079cee98c72ea3d54d5944164d7fb1cd92f854523225a8b0638759af36dd75a23ca7642acc9fb3e91c1ee3421177e0ee6b7795ea4ecfdbc2a062cb6bf2d18cf26c827f8cd73941273f5c9929740b716522aba9014e7a16e6c32baccad5939c9426e9ea9e620a15e7c71573d4a48ffb847ea1e59747e4b9118da58bae1c08fbd817b8145506b3995bc93d8a2b9b3632544b38f3fe243c5dcfa91d7b557b6af2f19010ac71f5841b570816083a49c2f1784d21ae9de853fe2d7e82c9f4950c4bf8222b2c90ad93acccd9de961e48a05a4a97a7dead6dc9a0497475a3f543c49037c5dde54870f1e8b67f66aebe2447c3b9202a553822d4751ba2b101a8aed8b4565","asset_commit":"0ad5adf475e147625992e9ef6378201921c979f97524933dea2faafd76eda81fe4","surjection_proof":""},{"features":"Coinbase","commit":"094c94cdf9863e4c4625b82beadbe136b6c9badaa0da0e67e6c75ae18c0970cf9b","proof":"7b850ae6f26f67d6136cc56e4f89306f01f829c14b51bd79c3f63929ab94501dc42d13a6361430ff60cb313314b901e64f44d620969b7c5cf098a3ef0b43184a030244b07edf40df1d9b7807d7a4878f22726ef740840a82378ce304f309d110782efe16c33a01e2e0c975132c41d828fde6c3a50cb15a10d52698359206fd48c2c5c415969a3558658a7bb6a8a1aae4332bb373e3378d6ffb9ac885e2781270461f0105f953af3b0e93872cc5209591561901c6a605d67a4fd379501953f569eb6a3f8ca1c7f43673c2de4aa9e9bbe0bcb3e4ab6212cc73043ab39d423d40fcfb04e833f1ba1ea6930b21ec42bda0ed66f28742517d51bc73f3ac141cbb32769fd4671cab8c3f6e532595340f1d20edb527567f6d66fcf06d48ac8cfa2a98b0f6b2519aedbd4267f02e4fd93b7d7a36ffa9cfb48970b71e154b823a18656cd1486686d08d6a608d46c8478598fdef821bd6ec3d140144c9c329ab6316302666ed0202aa27ce1ae8773471d490487e37da9cbc0525ba0b23dfdd1af4832baf62af76e83f7a2123cffc8c677dccc6f987e6efd8a84156b60813fc898fa5467d44c424eddb932f5137af408367ae2e7007fe86901c419ba2f29b6282bcac84b96667cf3b81c96bfaf16ba20ada36a9a3dc30d16cd72e52dac9adacbf7351725f029d63c94eb99842833e533c9a6d122306157238b908f46dba32ffaf8f24d74b64ace34f43ac2f72a65a436b1fe7d3f50508463ad28e67ec06075950c2993b86a297ab3da8fec79b8992fb9fcddac98234571d7f853ba322b319caeab5662ea602f0dcb7de35afd2426e611ba49ffd32ed6ca9140beba88ea256fdccdcb78c6ea0c92de26b7f5ee1cd22371126b33db125336c9f42b5f75d69e2ff0345e498b6026583da2edc4deee2f9ea92cda4c45ab40da58e83290224ef99d7442aecc686db34d030","asset_commit":"0a0ae867ce271250ad57f2c98d6e16f2393882a0bc0aa4ca9bb6e5c13cbcfaa212","surjection_proof":""}]
`)
	kernelBytes := []byte(`
[{"features":"Coinbase","fee":"0","lock_height":"0","excess":"080eaf25a928759fc3541ead4caa2b94df957328e20e0cc580c3d421cf87999a62","excess_sig":""},{"features":"Coinbase","fee":"0","lock_height":"0","excess":"082b4b3fc30fbfe29eff86bd0b47ca873c25b0eaae60a92fbff4a92daf6a55e6be","excess_sig":""},{"features":"Plain","fee":"0","lock_height":"0","excess":"09383fb8bed2c4d5e85e78f5c865bc4446115fad50445ff87cebd5a153597c6fca","excess_sig":"ea1d420ceedf7589feb7e685afcb89b6c7498f6ae49d8bbbea046b410e9fed0f6ced8b9933396f6af4d6f5e8ca306c0c379f2d996d4266b1caefa02e3114b476"},{"features":"Coinbase","fee":"0","lock_height":"0","excess":"093ab6fc5ff534c0cf771c6d26488987453e4096499081759bf8cdac9af5f8f830","excess_sig":""}]
`)
	assetBytes := []byte(`
{"apple":3,"dollar":10,"orange":5}
`)

	var outputs []Output

	err := json.Unmarshal(outputBytes, &outputs)
	assert.NoError(t, err)

	var kernels []TxKernel

	err = json.Unmarshal(kernelBytes, &kernels)
	assert.NoError(t, err)

	var assets map[string]uint64

	err = json.Unmarshal(assetBytes, &assets)
	assert.NoError(t, err)

	msg, err := ValidateState(outputs, kernels, assets)
	assert.NoError(t, err)
	fmt.Println(msg)
}
