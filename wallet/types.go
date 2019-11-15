package wallet

import (
	"fmt"
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/olegabu/go-mimblewimble/transaction"
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
	transaction.Transaction
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
