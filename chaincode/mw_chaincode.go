package main

import (
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/olegabu/go-mimblewimble/ledger"
	"net/http"
)

var logger = shim.NewLogger("MWChaincode")

// Validates and persists a transaction of Mimblewimble protocol
type MWChaincode struct {
	db ledger.Database
}

func (t *MWChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Init")
	return shim.Success(nil)
}

func (t *MWChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Invoke")

	t.db = NewShimDatabase(stub)

	function, args := stub.GetFunctionAndParameters()

	if function == "transfer" {
		return t.transfer(stub, args)
	} else if function == "query" {
		return t.query(stub, args)
	}

	return pb.Response{Status: http.StatusBadRequest, Message: "invalid invoke function name"}
}

// validate and persist transaction
func (t *MWChaincode) transfer(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) < 1 || args[0] == "" {
		return pb.Response{Status: http.StatusBadRequest, Message: "missing transaction bytes in arguments"}
	}

	txBytes := []byte(args[0])

	tx, err := ledger.ValidateTransactionBytes(txBytes)
	if err != nil {
		return pb.Response{Status: http.StatusUnauthorized, Message: "transaction is invalid"}
	}

	err = ledger.PersistTransaction(tx, t.db)
	if err != nil {
		return pb.Response{Status: http.StatusInternalServerError, Message: "cannot persist transaction"}
	}

	return shim.Success(nil)
}

// return all or one output
func (t *MWChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var valBytes []byte
	var err error

	if len(args) < 1 {
		valBytes, err = t.db.ListOutputs()
	} else {
		valBytes, err = t.db.GetOutput([]byte(args[0]))
	}

	if err != nil {
		return shim.Error(err.Error())
	}

	if valBytes == nil {
		return pb.Response{Status: http.StatusNotFound, Message: "output not found"}
	}

	return shim.Success(valBytes)
}

func main() {
	err := shim.Start(new(MWChaincode))
	if err != nil {
		logger.Error(err.Error())
	}
}
