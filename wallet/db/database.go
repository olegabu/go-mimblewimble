package db

import . "github.com/olegabu/go-mimblewimble/wallet/types"

type Database interface {
	PutSenderSlate(slate *SavedSlate) error
	PutReceiverSlate(slate *SavedSlate) error
	PutMissingPartySlate(slate *SavedSlate, missingPartyID string) error
	PutTransaction(tx SavedTransaction) error
	PutOutput(output SavedOutput) error
	GetSenderSlate(id []byte) (slate *SavedSlate, err error)
	GetMissingPartySlate(transactionID string, missingPartyID string) (slate *SavedSlate, err error)
	GetTransaction(id []byte) (transaction SavedTransaction, err error)
	GetOutput(commit string) (output SavedOutput, err error)
	ListSlates() (slates []SavedSlate, err error)
	ListTransactions() (transactions []SavedTransaction, err error)
	ListOutputs() (outputs []SavedOutput, err error)
	GetInputs(amount uint64, asset string) (inputs []SavedOutput, change uint64, err error)
	Confirm(transactionID []byte) error
	Cancel(transactionID []byte) error
	NextIndex() (uint32, error)
	Close()
}
