package ledger

import (
	"encoding/json"
	"fmt"
	"github.com/blockcypher/libgrin/core"
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
    "commit": "0980596ec61a13a445d49ab6b9a14bbe29d88827a723aeeac12d1ee0b3ed4a1882",
    "proof": "086b8dcf66ddfbcaa93513e795c1e2882a75d614d78312252a5cbd83fb436e563b35cc2615c7905857b58e604529f3f76b4dc1e56b2658fa82d79e6f4a961e26038a6987f949d7982e732ec4f53762a6c83dc1feb3b41839386d30d6776907938af7dbf52c0f0f54979f877735eff39a07e3463e201be8c8cf35849ad744e1d2bb7417ca9e5836e3bf36d94258ba03bd7a478fd18fa6ee7820f11e5c43c23b2d18d217307b09a05441a6daa75aaf185781f73532b73afe7a332d14938d84021ef5a6aedec66042ea5ee8350164877a50c93307c9d9b1aae7975cffd65d79d48ae4bd9a1105dfe9b19b3754dbfc63a8081dc22d78b5b9153f041001c83b95a65d141205b045e44b9308e2120ebbf9a11b29c335c57046c514c969fd13dab9a791d9e6292ae1c3f4c52afc5a3f5c7b2d077479047a52631388f34bc6bac65f2bfa95a7823e5e53fc4f514eaeb1020d15619267ec05349fa7c03706fc26604b913c6efe02725a98a32f477213b8855693552b313305e5cce1aad3ec2e63d594320597666eae21d51649b97e501a3062c8fd152e087fc2d59a2a583b7d9c6e7ed7ef4eab5e08e7b956c41653471ae5f2baf19c1f0107312e0e7d4c4a5e7e48ab293f2f860a484c913414f4ffe4d06626a515b2460a17cb3c19c6bd6d81b8d31664fccc342649399001387f3997ef8614eee5e7f45ee159e8eafe5256f132d94adca2ee99b46afc950792687b8812b2628d37679dc09782962694ec91d692b8414493c8f432983d7070baaa48d937a96ef750d8ba0654be7bb5e46c1bd0e2c622ec97f8cefe382acdd920af52f9ce53f375b5c4a0334cdfbfb948610fa1c435b3abccfb23f614db476723a6e78512c1ea459bb82869d92d4407f8f8561675fb1af571286f849b524d9874dfb366154d164f7089c33cd7c253fc8dd43ae68f407cb0730cac6a"
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
	assert.NoError(t, err)
	assert.NotNil(t, ledgerIssue)
}

func TestIssueInvalidBulletProof(t *testing.T) {
	bytes := []byte(`{
  "output": {
    "features": "Coinbase",
    "commit": "0980596ec61a13a445d49ab6b9a14bbe29d88827a723aeeac12d1ee0b3ed4a1882",
    "proof": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
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
    "proof": "086b8dcf66ddfbcaa93513e795c1e2882a75d614d78312252a5cbd83fb436e563b35cc2615c7905857b58e604529f3f76b4dc1e56b2658fa82d79e6f4a961e26038a6987f949d7982e732ec4f53762a6c83dc1feb3b41839386d30d6776907938af7dbf52c0f0f54979f877735eff39a07e3463e201be8c8cf35849ad744e1d2bb7417ca9e5836e3bf36d94258ba03bd7a478fd18fa6ee7820f11e5c43c23b2d18d217307b09a05441a6daa75aaf185781f73532b73afe7a332d14938d84021ef5a6aedec66042ea5ee8350164877a50c93307c9d9b1aae7975cffd65d79d48ae4bd9a1105dfe9b19b3754dbfc63a8081dc22d78b5b9153f041001c83b95a65d141205b045e44b9308e2120ebbf9a11b29c335c57046c514c969fd13dab9a791d9e6292ae1c3f4c52afc5a3f5c7b2d077479047a52631388f34bc6bac65f2bfa95a7823e5e53fc4f514eaeb1020d15619267ec05349fa7c03706fc26604b913c6efe02725a98a32f477213b8855693552b313305e5cce1aad3ec2e63d594320597666eae21d51649b97e501a3062c8fd152e087fc2d59a2a583b7d9c6e7ed7ef4eab5e08e7b956c41653471ae5f2baf19c1f0107312e0e7d4c4a5e7e48ab293f2f860a484c913414f4ffe4d06626a515b2460a17cb3c19c6bd6d81b8d31664fccc342649399001387f3997ef8614eee5e7f45ee159e8eafe5256f132d94adca2ee99b46afc950792687b8812b2628d37679dc09782962694ec91d692b8414493c8f432983d7070baaa48d937a96ef750d8ba0654be7bb5e46c1bd0e2c622ec97f8cefe382acdd920af52f9ce53f375b5c4a0334cdfbfb948610fa1c435b3abccfb23f614db476723a6e78512c1ea459bb82869d92d4407f8f8561675fb1af571286f849b524d9874dfb366154d164f7089c33cd7c253fc8dd43ae68f407cb0730cac6a"
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
[
  {
    "features": "Plain",
    "commit": "0814bade0139a95fc55cede562a9c0579b7992ef83ce68aa7442875a91f72554f2",
    "proof": "935d26ea14e22b65029ce9e764ec138406389d98aab7e924e1579f04d75294b5571e706053f9adf490d2445e5fcab89a1c5120f919e79899da36ec7a9bdb5af400c949700a558dfe7b3ef180d14eadf0f44c773b261c8840ad269d6d3a98aa51ab7fd7f748b0be7d718cc8049c53022ee0164ffa1216a8f1f34b024c0f64bb7f7fc2cba84e300383d5ab86f93ba7f682721fc9504a0ec9f78242c68bff834a85fe34cca13f0972bb54c683cce90b809d1e97118c5642c58729e51fe2c500da8e5a10be03b4d09f1c5acd1f788b442a0b6ee74a2f74260e4a836351b1d8b2ce55787c19e8d3aeafe5910191154e941658611021c2d16944ce6a20671313c4ae7dcc934e30e5574879508b04a6bfc705ab751fe6bcd843cee8bffe2127881406a9657fb24d352c4dc55d4950d84cd48d8eac547d280b074e4e7dd78b93aba2aefa958ed19db7e08a7678c7d33de17f7d92ba9a0eb0bd674805383f2befc821de5f8bee004009f8b23e78d117475147de35abb95eadd51a3a72d9c791bfe1c33add5d93c4c33af96e97dec4839732d525cf7d36605e9b3776856fa025bba4e69e8cc107e952f8abed494fa50ab5d852061ea73d4fc64a2f71a30a01cdf39ebbccd92d29450ca3d52cbfd38b1812d8b92a45a48c2eba1bb5c4bc53a3fc08aa1e123f32728d6698e343e4f2266e1a73f9122d3a89279fc00f3110486c389dec538b6438643d9502d19e6c6716bc6aee785cc2b9b79347b5518a98665cb9e6e6469b5ab6f463439854c01f00183a7bd71be76a0bcbb413885da8fc3123c02ed48f9ec401a59f7e997a10b1793ec91ac40017e56d1159d90cea2b3d675b572ee516c34e6f81a2eb6d07df5bdff7ab8de0b4abba277b0f3ba736dac3595e6465d24e8c5bb8a38cc90de5c7e1ca3308544ab98a1dac95f223f953fc89667a52d63590f4d282f4d0"
  },
  {
    "features": "Plain",
    "commit": "081d4fafb5456e4cb6907ba9b76c6a5cfb43c9e2233fc93bcd3a4eef564e7a0884",
    "proof": "ec054d5709ca9fa1dfd3c27eb9070436d7c61bfa991c1f75c9e0fd9dcfce4860944ef7647bceacbb4f9aaab08e6ce295477bf3564c4700f7d5e4f0b3424aff6607392afa03f95dbfc6725b060911a47cdefae5711274dafa0bab03ece97ad37c03a85b6b01449b94eb3b0cafc0a93d240f9061a774c1623d371d07dc87070d2bcd9c6acdb92b6714b60148e9d50f631df7666f167b99fdeb3f8f4837999034348703a144921b229cb543cc7032ae3c44126b9fd9aaaf7c45ea0bcb8a5103397d48f39b95cfc0daede601024674e536fa1141300a1eaeeb9c14d0f4d2a3581dcd45464853409abed6f575ba6c4df679a08b324c87eb9dd949a265ba852201fbdf1ab851638f8d8e96f74727c9bee9048e0e102a24bd60fe0b67d3557a608bed0175cfde0d5e06cb3c063c700ab903b32bd6b945e64fd23f1b9c2b21cbfce6bca0d8b0a8c586fc2432134068bd05a7c124a8d805f68f4cf81693479b88bb1117c458ce032ec9a2cac103d54e706946d39ee0fff9f45ca7f3b5a1088090eb4c1f4e69a92e30f6f10d960ccd81aa9a19ac0681a54d7c7fa40eadca441bf5333eb5da738a59a9fc6efba17d38078474a9a9d0288999ed9b5a9433d4e27d239fef1c0b3e6caf777fda89c59fbafcaa2960ff78a7a6210656160c9914b62474f87f518963e4d64d43815e6b6b08861bef65d06fa44a3b3e5f06e2b662e3d51fb79bbacc7d678adce8fecbb0a20a09f8613a5974db77d78ccb9e83a9fa86bcd17065d04b96ad9010fe51d33306a8b9c4f907a0f88a8bf8e863bfd303ae076b936d0c6f0f0e8c48c558cc12c674951125fcb9a84c00698614f960e162485f170d091f46f6d7232e1940a2e35d8c9546cac2bbd2fb4ee49c4d3f5f3a6478c050d3fc2ce6921c7a1d9420947668a37f65fa0287c680cee1fdaf074c00c6cdaf230180c0b526db676c"
  },
  {
    "features": "Plain",
    "commit": "086d3e2b2f6644a8e497a96a701fcdec07cad5084310248c4eaa8ed2fff15a4ba7",
    "proof": "bbebf36c6bbbce80202b8cfcb74476562254efbc4772aa38cd0d5cc85c316c3b83c527563e5bb1d533df1c608dd0860afb8a1e3cbd091aac36fd76f29c4972250d3469126a1be2321c15536023960200b6013b58bd3c8429ca9e5eb38163df38ba68d4795bdb5432715d686005b43953d72bb2b4f4b1413255335539b66f6bcac2d416ccbe0dc37825f53a7e18187713ac669d946bc18f05fc536b1c0546ec432df190743b22c47b4f9178094502b95df23b2990ccd3d9c0fd10c98ca08b0f5053c9f994296964cf861d6d76e920e8ce6436edc3f66cbcdfba71b2c096c39084f04e2255b379731495963afc14443d76e1b6435f7aded7cf86f85ad7fea405ca936a3193a01d903bd873b6ce4acb8b1fa792c9d87a310cc96a98689b649dd290f1ecf83c7c196dc0ce8b49ddd0187635a6bddc3fd5e222a201965b24d5bc26d608dee12ff0885adfc3756648c6b407d207ba88586e16edde3fe109e090c86f6dfa7b00bd6fe7d981929c5aeaee828a6f8d64baa56a4a378dc428f02ffc469dbd290e3248b3bffd7b37a0c4fb2c9a0e7239cda955650c62b9327a4e434c3589008706aa04b0f4ec2a02d31a7c17d8b22ecda832a045fa2eb924a1287d89e55da9aa34cf2bb547168edca007aab13ceef51e74255fae3a6be7836cf50747a91f6d18f70974ba4b3dc9cdc668d784023ba1b75827587f9c05afd8c38bdf3425496722b0fe2da35729f0cded5deadd1e916776e444ea27547acd8ba5181516148f73f677c366aeb61f42b51cb8e11d61b768fd1a44abca91eff6f20bdfc41b7fa21d3e435b3a4d3150df51c2239640bf5b703f5ab05215dd0cf228c2ea2cdcc768ae5e40acb49a68ceb5ef8e172215ba04f2ed1e9925f930fa1acc6fd726955228d825cf32e4800ed3da6098522a88aec129cfc7bcebc08d43b8ae19a48c556da527deb6f9"
  },
  {
    "features": "Coinbase",
    "commit": "0882e255c2d54eddb237a4a23dac4cd410d64b3a4b21d021b5f8c9cc2861a474a9",
    "proof": "004793e88c0fa3087d41cd5b03f9e3dda72d7ddab9702c12daa1cdf49bd659e05fb0552a23b5d1248ba422ee5c0750f82124a5a947a4da290799e36ea2131925031b8a23d188201fe865e55a69cad3cac834ec18e9e74bd1c9a5142ed96e1a3296952fa71896b83b58c3eadc4b1800beaf06f2875c374b588fcfb7a7af11d7977743356dc14e5a0f2fc90f70c1e669684cf54c97db39d065e53aa29697596b06d6145b8b28187c34e772c7642c4a8f2b0a84e5a398078c02cd6a8785f1eebca174a853997b39fd50eea5f3e421abf4c9fd61ba7c9fe622b3e3e8fe5c57524875f27c0d7a45a71247e6e56705cae22861f1b5f41a1b23674fe6fb7c0aa4185018d30aed253fe1a0211be5807839385ec8ea33ab2ab55f0af7b7e596b5878ce6ccd4eff318b36c018ce5eca2a2d1b772f52c30d4bd013394e0c07d8bcceb047bfe3bbf8cd5bad2f8ea4ef82ecd610a37152c977b736f6538aee2feddb28aa8f915c47602f97287877708620ba9f6099f4723406408bc0f7cf2008a6beff44c35e7758f192575ff54c69d94c42e65aea8a88bea33bc271ad358168b0d9756488b996e6391c3972262eec3066759ad0edf1a4d2567777f13807f28cad9c786d8e8d3958d01c823bfad128639c33a0f8cb3a57c9347f22ecc48ddc9be5cf934f99f90df42e98bf38cc01d9a25eb68400390e9740461eff00f7c632fba1f2d59863f2b2e474a23f34ed2bc575c690ffe61b685c7922ca3b1cd2d7eb3fdb0c4e8d1db8e939761c001b3aa26ec91b3cef8999111c0a5c1f06bb03858b5abcfd5adad5cb62316426ee64d2096dfbbdf87d54273d47a9efd1a754b9f874a706fb248e46fa185bb22afdf394eb2f3daf4a62b99ce007eb3835c0c483a43ef3f9a8615be60954d5e69f88d2c1e69fb79e76569fc914ec41ea726c396a13b811e141663f162347faf4b"
  },
  {
    "features": "Coinbase",
    "commit": "0886d501f37ddce5be3bdff48a5a288b9338fef39bf59d3fa6c46ca96b4fd6f6d4",
    "proof": "3ad19cbe6dd0a60577c261ff9cacc3e6b3dba3a18ee8b8276178fe47fcb16c6542d0c4a4797b8e6b9a4c7c2ae9fa593620e208c3473f6132fc9f226ce4f894a600d65c8861cd1161198c019a81d0fac6e40e336eecf4d8fd3a4531c28eda859f58c0ef854c6e7c3b59a4b0ccd32860741ccb1f3a9bf1614b307ba9759bf4885689290e8b8fe706b1851cf38fb82a7c86b5ca7899ed2a184d15b613cdd94521cee3d50a4cad1408a2832ece790740b59cbe5a9583777fbba093eccf832abb8cce8216b1f51ee48c5e5d6cbac3449a20b4f0ee1609b6a4b55ee31791d4197431297c3f20e7b81c8ce9c7454af1d60d8821cd152df58ac9f541a421afc5342e2a21b8b04e0da505cdadb65cf03810275d464e09db28da0cd17f4a7b639d93e52c0802e4510f4f237342c68bc444ae7efa0a3bb95112bf8ec2503f1c80d4da85ab5d5eb3d2fff6dcd452db0a16c6ed592d16f17feca9402c6a66f7afbab5dde2bd93e99b02c876e19ab9df9e063424c0062c6e21409fcdd2da809f6d83eb0f3897492c30e755b532b59463923d96e1b7d748ecd55f312b19ce105fa5ce17bd05a91c948d4c028d2a4cdf0842c4c080a17da81e74c4cf09d92f352318f0c40ba7062380a02ef07b37b5a04eab6c6b4e3924d83e8f725b0e0690a6715990d37206666155695db310641be5ed7339678fc152ad234d976fa7287f7a27ba6b36b52e7f6f67d363ece2a604f398b02d527505f5c9635fba617614695ce70ef6d1f60c923019a585205fec8291fde7fbfe1305eb1043fa0ff2cb85a053a1c85e988ca97286cf6bfb28ea7c1254494d5a91ca0ac58c38b2ebe5dffd60d3f92d93a91f57200b55e131a512a0b23f2b1b9e29fe7583285ddda36a9b334f0656f9168f54c6d659b81822b085b829a09fbaa699004c4488c5658e8f337f8169e69be2f41e5c377a066c97"
  },
  {
    "features": "Plain",
    "commit": "0896a4322b29add39dea87aa3a85b8dafb58de996377c1816b91dc246299e7b970",
    "proof": "373cd299b7097206ab0894596b2f55f6f503c306564d1db91884ec553d3a3d84745000a38de83d8c1d8b9953c5fdbd7df6135cc0e07747bd8ad838c4bd74930f09d4033e537c93c10ec481e8aa068be337a06456f1d565ef4f6077e3bae1966ae9c1cb5eae5c5884834d24a0217d9343a586d6638b5b3d52161258455aefc685f0296d09c687beb35702a2f23a8d1aa4fe4223637047b3b88cf81e0eeda76d0c55b3f0e4defddc65351bf46ae2c139bc80e7d85e1ddf3259d886463e06a5d44f67e672a8dd202935951279402ab48f31237c8be3f0f55fcf0a0c1b07a7085e5ce99dfe572584facfad54eb05a56b8307da68dcb87f0c2cf0e628ed8eb4ff55395273eaf438cef29e3e3f1aa9d0ab54e0fc005714f56618cc6952c13f3460fa10d6d3f3ddcfb58ffe45d0a4efe69e91560aefe4a75c5d6a6d4430d7f914afef6a44e36d455f1ff7641c47bf2e71c2cfea1b80a6f0ae45568974bd467a46a8c442bf5601faef227f8c5cdd357fce3e199d44096b7823bc988c64572b8262fa815651efe1983f8ba03675fa5636a821367d124fd50b8ff621addb875bd0f33cbf5553ad46cc1202e73f190d36fe0568d083c99a9743edb601f045acf6e0ac5fd102742a81f80926e4fc9c2ac5fed343b39ae1bceb42a0cda8b104e130cb96efc0d0784438b6f98bd3073f4a7dc12b0cc212c2bf5c32c68a898f95039aa819b40bfc2201f8874b8a37da5c730febe85e717bdfee3daafdd80bb03785e67e95547750f1bb6af14e1a56e43647c5a313702b8968b3f64194cfe77a12d468bef1cf6eb6c74d10fb6e4d894ed7839c30c8e9feca998c0ff7016e268b3b536f938a5d993df4f6d93009e1f8e0705d8b4451ff5d4532d8592f6a742d5ab12e008370a716cef5c3575115989d750c356b9c8a78ac0730b6c044d35875297ea1a3cc232c6a2f98d2ec"
  },
  {
    "features": "Plain",
    "commit": "09950b7ebdb3c5c30b7c0e6cc0e28808d33ccdebf889d6c532bf66274c82ba3661",
    "proof": "4ae0cb83defeaf3e5163909690109fd75fb7502adeb12799d7a21e634020fb9ca83758b8da73c1ceb8c76edfd60a8b27a8e77c256edc12ceabef89a756fd6f2e0dd7ee527b0a2a4534e04b4592d8340396c030475a5ad539953b7fe196def471fa71d3da317f5283a0b861b9398b0d02a990a365fd15f09dde2ede471d370ce153231264151c5bc1e1da095946156c7d1023979bb2a88f3c74b9ef7a970db90f747afcdd8255aedd304decaffe03ac894f2e9cf49d4ecf3d4b5e6444a4460b384e80271e413522a955fc0d8bae476e97974fc7f38fd87356c3b9ba9b0ab40999c5b54a49379d6935500c8e7621d6ad3d3bb6a3bbd6d6cf1acad16cd65d4a54f47012b995c844c5a834761221f41d8922df76c3d0c4802016cfbcabc2e3db14989508d979ff78668de75d2a70fa1d1099745425aa8a1a81112947320b926049892d324ede94a7c1ab4169128765571f29a386048f00158250b70a36df356fabbbf8240172dbfd98ae2b83ad15ef53cffa381d981c73caba0cda6772f6888c3d2154265478366a95611dbce061c3ab668c6f1c619b32acf8568f369435cdec6e0178643f8aa67b35bb909dc5ffb4ba19cb283af5845cecf8306b4fc2ebb688f039dcfd9169d03c81c323181883c06a229c51d8eb9d5cb843c6ec904be39f0f6d43e29747427c4b4e535a8f529e1d72967191a769d9880d82309118e24d59d68e293cf007a665abe631508bb409fd5808f9bb8cd0f84171880719a880a9175c2cbd9b3da4d3a45d3d9f261bd35ec242d6cb7aa165def541e500140d6762064118fc1769976d4f41e85f9af0d62a3620444afbfa47007844ad1fb3cc68997a3ff324ff3e7c59a9a887bbf2f25830bdf9ef1f02093102521a2da358b05a951be57b20fc8e2e49f926d4af81385d0216a78983f347ccb5c3fa8bd23661cdfe82691fdbd42c6d"
  },
  {
    "features": "Plain",
    "commit": "09cf9db9f8a6dcb969e7fb8a05996f6a9536680ec82efd56b68d714a466a0aad94",
    "proof": "1eeba091c970d0bebdf0871ecabf4af4dfa8d131e824e22e5b02379f8edd8cb0a717be8adb6770b0b7d5ff8ec00a157ce619a7fbeb4f2ad3e1894dd967b399f70fb45a5df4c354efe357adabed86966990d5688383430adac2f791f391466b78746622f502ac2d64e21e24dcfbcd16ee691b707519667e059fbcee4f1efb50c489a9925774583244e9ebd0e8276034caf5e6f5d25731e2e29b81e48e794c95795234d9fd3ce8945da894f0f88d974ce1f0ae6e98e196950c23937f44e77dc847922ed7d0b09baa77b5bfb9ae48e8e8033bdef8d75864fc6e2dff91b72ff490d49c3d0ab36708a5f23f8858db64a47d3199a78ffcfc83d0e6e0b798f97f62963030bb1ecca7b01332934cdb7a0041368a66813b17da0f152f8cbc0da21dbc70e4e6f58342452b137d1b40ce775392688b66f727459cddd47d35c4c8ba04d3ee9cee9e94cf4c6e5aee63241b88d1163566aa760e5a83e5b11b9edb139e6815280a08fb011c9faa19576ceb941f3d6850d0c8fa9a1852f28b4cf08effd214878f7882badbaa22e9c5343766ac13f3da2740c98de80737667ccbedad8aa40f4ae40d93241309f43fefc5ae9181f78b5347f8e1678cf8001e8ff2bf813c95a0dd14663dc4cdef6bb571cf49cd4f55c02d590d0809eb09dfd7011ce827a9b13b2595c8cd2792fdd0b8e3d2516b9a515333db97329c058b28edfe35e51931825b4a647c5115f0155a2a0c602c41dcf0257294b060766b8c8820af1eaddd942b899a2fa8e9a30c6b07cb5f7d8ce178a494bca8d421a838d5ea36f4cfcbf867bef471bd79be6df9a9d4b1100efce7018d90c4deb9128c1cae0028079378f65f16c27df7f6cd8dd255bf2bffe7a2144b523e8134d55a0514e32da9f021fd8ef96c14561a8343e5871e64a944b9f95f3545d159a3c390c7fc1178148bb1b9cbfa260b55fc22dd1f7a"
  },
  {
    "features": "Plain",
    "commit": "09dc7ae3ceec6a13aa08739b3717670d2398f1f456a6042d2f0373aa1227eac1d3",
    "proof": "53afc2b3fb682c8046fc47aee62e94d7e07752a7bb07351c1f8aa5752d5daaac1a4b2d49122e7b74802fd943d9cd95922f1f5754182d44d058fe6b943554e523093ee9077c17f95c2562eb773a206822fc46efdf07f251efa8be79c2d9d1f791aac36d0103d00ba2bb4067fd1875af1a6eabdf6ea672a7ecc95ca93f2210a06c6aa344762d618ca6ee89278cc526d24593a02eaa6ae58a99cd047cfc01698adce1395f1d80a34e81d89a01332b3e1492bcb36e660573f32a93ca145d269f0c3e1f65bc7d92ff25903ac315eaaa47365a2136bbc6f361189a61851308f205e52d058e6bfc160a2fd9d27b6833f49b23b3d8ba761c17d1944ab52a3a9df0c1486eb3124fcd6382feef7d958a5e59fa6dc481b2d94567f3c510ddcf550f419ced39fc45949db8cab7c3dd640ac5628c4b5cf62c0856bb1137644123fcbd38c68f646e8d5d233a6a1d5490924092c0c1d9dd2732490216f09742007d5bee29e0d4f3cec7008216bd051fd22f21ab64fe986ec2e11727d253d5035a0ca67d360e2d7b21d0def05911468a90aeb8608da87cc9d635500bc1be928bdcb7070433a883770e127162efd655e022b00f56ae69075814fbb50a2c6077f617a907f1932b39d0ccf1a0855681a09db693deaac87711e8d07f790a3e526a130651cd99fed492c0c20ce6b5e3f8977a138a81a23a277ebf9cff0889759b2af62dfb25e38001b3ae07c60de69d74c82ed3a929ce14abe68c4b00560527838c17efb4a9a81cc46b8f2034dabeae76b4aaefe5824077bf0276f912b0c79a62dcace3ce8b662f1937dd0213f171f5a491e5fdb51ba4115d2418f8a0e1d082dd2a01fc2b06bd01644973fff4521f524190d5aebbc102f43f52b9eb26774eb4267dcdd51aa7ed8f17ac2f34e07313c8f7db2bc243dc3703f16de850e1ed5fcf8480786c53c1eda8312ab096a1d8"
  }
]
`)
	kernelBytes := []byte(`
[
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "0825f46a638e02607c99b3e1fb9dba5087069d6c67127fd13f9582680a0cc384df",
    "excess_sig": ""
  },
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "083e937d90601261f7aeabd380006ce1cc4e191681de853a72efd6b21b7b5c3d21",
    "excess_sig": ""
  },
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "0871d0844c1f3c2ae4c825839620640dacacfe6d8464ff18fa1b38b3e6d5e6e7bf",
    "excess_sig": ""
  },
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "089d83fa4729df0f848ef79b035c336c6b1909de575378ec644a2607d95186bfd6",
    "excess_sig": ""
  },
  {
    "features": "Plain",
    "fee": "0",
    "lock_height": "0",
    "excess": "08a442b2574e5109085e7d66229d3426e13af4c2f4b3cffa6d8d62e0a8ba197d6f",
    "excess_sig": "8fa957d84180ebe095e978e1b21cd80b4ffff4be1836f30edb5a0ec2d1da123919777c683fa9dc4804dc1e916ba6a7c0cb945a5aef74e9da238aa3efbd2d0a75"
  },
  {
    "features": "Plain",
    "fee": "0",
    "lock_height": "0",
    "excess": "08b05438f0cce15b72ebcc46dab7ac86085de411ec586a5805bda4fdf19fdd8bd8",
    "excess_sig": "868af987663d75ca4a4dd505fe519af9348cd5913428e41f2116914cdbfff482b89bb5ab6641440be1ace69145627fdde7b24079983943378581e4ff1ec96e9d"
  },
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "08b9bc82a0c2c5e2d9e1c5e1c65f344d1c0f23e0a46f2be19dabbfa164ca9d908c",
    "excess_sig": ""
  },
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "08c00526117b3cabfa2250059b11b211aacf3dcff9deb196a850d5ea84db22b71c",
    "excess_sig": ""
  },
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "08e078c94a529d59d7bc8ac76306749cd18e1e28d5114c10c123854c24f2f336b4",
    "excess_sig": ""
  },
  {
    "features": "Coinbase",
    "fee": "0",
    "lock_height": "0",
    "excess": "08ecbf07ac8ef2b31b93fe35cc819ea63e938e26c238c543de54cc4303dbf4cf50",
    "excess_sig": ""
  }
]
`)
	assetBytes := []byte(`
{
  "$": 6,
  "apple": 9,
  "orange": 3
}
`)

	var outputs []core.Output

	err := json.Unmarshal(outputBytes, &outputs)
	assert.NoError(t, err)

	var kernels []core.TxKernel

	err = json.Unmarshal(kernelBytes, &kernels)
	assert.NoError(t, err)

	var assets map[string]uint64

	err = json.Unmarshal(assetBytes, &assets)
	assert.NoError(t, err)

	msg, err := ValidateState(outputs, kernels, assets)
	assert.NoError(t, err)
	fmt.Println(msg)
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