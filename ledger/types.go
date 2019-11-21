package ledger

import (
	"github.com/blockcypher/libgrin/core"
	"github.com/google/uuid"
)

type Database interface {
	Begin()
	InputExists(input core.Input) error
	SpendInput(input core.Input) error
	PutOutput(output core.Output) error
	Commit() error
	Close()
	GetOutput(id []byte) (outputBytes []byte, err error)
	ListOutputs() (outputsBytes []byte, err error)
}

type Transaction struct {
	core.Transaction
	ID    uuid.UUID `json:"id,omitempty"`
	Asset string    `json:"asset,omitempty"`
}
