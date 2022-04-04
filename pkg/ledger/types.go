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
	GetOutput(id []byte) (output core.Output, err error)
	ListOutputs() (list []core.Output, err error)
	PutKernel(kernel core.TxKernel) error
	ListKernels() (list []core.TxKernel, err error)
	AddAsset(asset string, value uint64)
	ListAssets() (list map[string]uint64, err error)
	ResetAssets() error
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
