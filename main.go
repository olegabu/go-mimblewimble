package main

import (
//	"crypto/rand"
	//"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"unsafe"
)

//export TestRand256
func TestRand256() {
	//rnd := [2][32]byte{secp256k1.Random256(), secp256k1.Random256()}
	//fmt.Printf("Random256(): %x\nRandom256(): %x\n", rnd[0], rnd[1])
}

//export
func CryptoRand256() (ret [32]byte) {
	//key := [32]byte{}
	//_, err := io.ReadFull(rand.Reader, key[:])
	//if err != nil {
	//	panic(err)
	//}
	return ret
}

//export TestContextCreate
func TestContextCreate() error {
	params := uint(secp256k1.ContextSign | secp256k1.ContextVerify)
	memory := make([]byte, secp256k1.ContextPreallocatedSize(params))
	ctx := secp256k1.ContextPreallocatedCreate(unsafe.Pointer(&memory[0]), params)
	defer secp256k1.ContextPreallocatedDestroy(ctx)

	//clone, err := secp256k1.ContextClone(ctx)
	//if err != nil {
	//	return err
	//}
	//defer secp256k1.ContextDestroy(clone)


	//rnd := CryptoRand256()
	//res := secp256k1.ContextRandomize(ctx, rnd)
	//if res != 1 {
	//	return errors.New("ContextRandomize error")
	//}

	return nil
}

func main() {
	err := TestContextCreate()
	if err != nil {
		panic(err)
	}
}
