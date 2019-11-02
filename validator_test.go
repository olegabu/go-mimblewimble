package go_mimblewimble

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"testing"
)

func getTxBytes() []byte {
	bytes, err := ioutil.ReadFile("1g_repost_fix_kernel.json")
	if err != nil {
		log.Panic("cannot open json file with test transaction")
	}

	return bytes
}

func TestValidateSignature(t *testing.T) {
	assert.Nil(t, ValidateSignature(getTxBytes()))
}

func TestValidateCommitmentsSum(t *testing.T) {
	assert.Nil(t, ValidateCommitmentsSum(getTxBytes()))
}
