package mw

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"testing"
)

func getTxBytes() []byte {
	//bytes, err := ioutil.ReadFile("1g_repost_fix_kernel.json") // fails TestValidateCommitmentsSum
	bytes, err := ioutil.ReadFile("10_grin_repost.json")
	if err != nil {
		log.Panic("cannot open json file with test transaction")
	}

	return bytes
}

func TestValidateTransaction(t *testing.T) {
	tx, err := ValidateTransaction(getTxBytes())
	assert.NotNil(t, tx)
	assert.Nil(t, err)
}
