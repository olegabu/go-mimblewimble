package wallet

import (
	"fmt"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/olegabu/go-mimblewimble/ledger"
)

type Database interface {
	PutSenderSlate(slate SenderSlate) error
	PutReceiverSlate(slate ReceiverSlate) error
	PutTransaction(tx Transaction) error
	PutOutput(output Output) error
	GetSenderSlate(id []byte) (slate SenderSlate, err error)
	GetTransaction(id []byte) (transaction Transaction, err error)
	GetOutput(commit string, asset string) (output Output, err error)
	ListSlates() (slates []Slate, err error)
	ListTransactions() (transactions []Transaction, err error)
	ListOutputs() (outputs []Output, err error)
	GetInputs(amount uint64, asset string) (inputs []Output, change uint64, err error)
	Confirm(transactionID []byte) error
	Close()
}

type Output struct {
	core.Output
	Blind  [32]byte     `json:"blind,omitempty"`
	Value  uint64       `json:"value,omitempty"`
	Status OutputStatus `json:"status,omitempty"`
	Asset  string       `json:"asset,omitempty"`
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
	Asset  string      `json:"asset,omitempty"`
	Status SlateStatus `json:"status,omitempty"`
}

type SenderSlate struct {
	Slate
	SumSenderBlinds [32]byte `json:"sumSenderBlinds,omitempty"`
	SenderNonce     [32]byte `json:"senderNonce,omitempty"`
}

type ReceiverSlate struct {
	Slate
	ReceiverNonce [32]byte `json:"receiverNonce,omitempty"`
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
	ledger.Transaction
	Status TransactionStatus `json:"status,omitempty"`
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
