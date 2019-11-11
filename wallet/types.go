package wallet

import (
	"fmt"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
)

type Output struct {
	core.Output
	Blind  [32]byte
	Value  uint64
	Status OutputStatus
}

type OutputStatus int

const (
	OutputUnconfirmed = iota
	OutputConfirmed
	OutputLocked
	OutputSpent
)

func (t OutputStatus) String() string {
	switch t {
	case OutputUnconfirmed:
		return "Unconfirmed"
	case OutputConfirmed:
		return "Confirmed"
	case OutputLocked:
		return "Locked"
	case OutputSpent:
		return "Spent"
	default:
		return fmt.Sprintf("%d", int(t))
	}
}

type Slate struct {
	libwallet.Slate
	SumSenderBlinds [32]byte
	SenderNonce     [32]byte
	ReceiverNonce   [32]byte
	Status          SlateStatus
}

type SlateStatus int

const (
	SlateSent = iota
	SlateResponded
	SlateFinalized
)

func (t SlateStatus) String() string {
	switch t {
	case SlateSent:
		return "Sent"
	case SlateResponded:
		return "Responded"
	case SlateFinalized:
		return "Finalized"
	default:
		return fmt.Sprintf("%d", int(t))
	}
}

type Transaction struct {
	core.Transaction
	ID     uuid.UUID
	Status TransactionStatus
}

type TransactionStatus int

const (
	TransactionUnconfirmed = iota
	TransactionConfirmed
)

func (t TransactionStatus) String() string {
	switch t {
	case TransactionUnconfirmed:
		return "Unconfirmed"
	case TransactionConfirmed:
		return "Confirmed"
	default:
		return fmt.Sprintf("%d", int(t))
	}
}

type Database interface {
	PutSlate(slate Slate) error
	PutTransaction(tx Transaction) error
	PutOutput(output Output) error
	GetSlate(id []byte) (slate Slate, err error)
	GetTransaction(id []byte) (transaction Transaction, err error)
	GetOutput(id []byte) (output Output, err error)
	ListSlates() (slates []Slate, err error)
	ListTransactions() (transactions []Transaction, err error)
	ListOutputs() (outputs []Output, err error)
	GetInputs(amount uint64) (inputs []Output, change uint64, err error)
	Confirm(transactionID []byte) error
	Close()
}
