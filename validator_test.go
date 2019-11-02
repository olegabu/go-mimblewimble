package go_mimblewimble

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	bytes, _ := ioutil.ReadFile("1g_repost_fix_kernel.json")

	assert.Nil(t, VerifySignature(bytes))
}

func TestVerifyCommitmentsSum(t *testing.T) {
	bytes, _ := ioutil.ReadFile("1g_repost_fix_kernel.json")

	assert.Nil(t, VerifyCommitmentsSum(bytes))
}
