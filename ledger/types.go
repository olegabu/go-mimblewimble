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
	GetOutput(id []byte) (bytes []byte, err error)
	ListOutputs() (bytes []byte, err error)
	PutKernel(kernel core.TxKernel) error
	ListKernels() (bytes []byte, err error)
	AddAsset(asset string, value uint64)
	ListAssets() (bytes []byte, err error)
}

type Transaction struct {
	core.Transaction
	ID uuid.UUID `json:"id,omitempty"`
}

type Issue struct {
	Output     core.Output   `json:"output"`
	Value      uint64        `json:"value"`
	Asset      string        `json:"asset,omitempty"`
	AssetSig   []byte        `json:"asset_sig,omitempty"`
	IssuerCert []byte        `json:"issue_cert,omitempty"`
	Kernel     core.TxKernel `json:"kernel,omitempty"`
}
