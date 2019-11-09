package wallet

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFinalize(t *testing.T) {

}

func TestReceive(t *testing.T) {
}

func TestIssue(t *testing.T) {
	for _, value := range []int{1, 5, 10} {
		err := Issue(uint64(value))
		assert.Nil(t, err)
	}
}

func TestSend(t *testing.T) {
	slateBytes, err := Send(7)
	assert.Nil(t, err)
	fmt.Println(string(slateBytes))
}

func TestInfo(t *testing.T) {
	err := Info()
	assert.Nil(t, err)
}
