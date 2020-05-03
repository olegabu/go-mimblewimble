package wallet

import (
	"fmt"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/olegabu/go-mimblewimble/ledger"
)

type Database interface {
	PutSenderSlate(slate *SavedSlate) error
	PutReceiverSlate(slate *SavedSlate) error
	PutTransaction(tx Transaction) error
	PutOutput(output Output) error
	GetSenderSlate(id []byte) (slate *SavedSlate, err error)
	GetTransaction(id []byte) (transaction Transaction, err error)
	GetOutput(commit string, asset string) (output Output, err error)
	ListSlates() (slates []SavedSlate, err error)
	ListTransactions() (transactions []Transaction, err error)
	ListOutputs() (outputs []Output, err error)
	GetInputs(amount uint64, asset string) (inputs []Output, change uint64, err error)
	Confirm(transactionID []byte) error
	NextIndex() (uint32, error)
	Close()
}

type Output struct {
	core.Output
	Index  uint32       `json:"index"`
	Value  uint64       `json:"value"`
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

type SavedSlate struct {
	Slate
	Blind [32]byte `json:"blind,omitempty"`
	Nonce [32]byte `json:"nonce,omitempty"`
}

type SlateStatus int

const (
	SlateSent = iota
	SlateReceived
	SlateFinalized
	SlateInvoiced
	SlatePaid
)

func (t SlateStatus) String() string {
	switch t {
	case SlateSent:
		return "Sent"
	case SlateReceived:
		return "Received"
	case SlateInvoiced:
		return "Invoiced"
	case SlatePaid:
		return "Paid"
	case SlateFinalized:
		return "Finalized"
	default:
		return fmt.Sprintf("%d", int(t))
	}
}

type Transaction struct {
	ledger.Transaction
	Status TransactionStatus `json:"status,omitempty"`
	Asset  string            `json:"asset,omitempty"`
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
