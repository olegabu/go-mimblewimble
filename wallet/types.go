package wallet

import (
	"fmt"
	"github.com/olegabu/go-mimblewimble/ledger"
)

type Database interface {
	PutSenderSlate(slate *SavedSlate) error
	PutReceiverSlate(slate *SavedSlate) error
	PutTransaction(tx Transaction) error
	PutOutput(output Output) error
	GetSenderSlate(id []byte) (slate *SavedSlate, err error)
	GetTransaction(id []byte) (transaction Transaction, err error)
	GetOutput(commit string) (output Output, err error)
	ListSlates() (slates []SavedSlate, err error)
	ListTransactions() (transactions []Transaction, err error)
	ListOutputs() (outputs []Output, err error)
	GetInputs(amount uint64, asset string) (inputs []Output, change uint64, err error)
	Confirm(transactionID []byte) error
	NextIndex() (uint32, error)
	Close()
}

type Output struct {
	ledger.Output
	Index      uint32       `json:"index"`
	AssetIndex uint32       `json:"asset_index"`
	Value      uint64       `json:"value"`
	Status     OutputStatus `json:"status,omitempty"`
	Asset      string       `json:"asset,omitempty"`
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
	// Versioning info
	VersionInfo VersionCompatInfo `json:"version_info"`
	// The number of participants intended to take part in this transaction
	NumParticipants uint `json:"num_participants"`
	// The core transaction data: inputs, outputs, kernels, kernel offset
	Transaction ledger.Transaction `json:"tx"`
	// base amount (excluding fee)
	Amount ledger.Uint64 `json:"amount"`
	// fee amount
	Fee ledger.Uint64 `json:"fee"`
	// Block height for the transaction
	Height ledger.Uint64 `json:"height"`
	// Lock height
	LockHeight ledger.Uint64 `json:"lock_height"`
	// Participant data, each participant in the transaction will
	// insert their public data here. For now, 0 is sender and 1
	// is receiver, though this will change for multi-party
	ParticipantData []ParticipantData `json:"participant_data"`

	Asset         string        `json:"asset,omitempty"`
	ReceiveAmount ledger.Uint64 `json:"receive_amount,omitempty"`
	ReceiveAsset  string        `json:"receive_asset,omitempty"`
}

// ParticipantData is a public data for each participant in the slate
type ParticipantData struct {
	// Id of participant in the transaction. (For now, 0=sender, 1=rec)
	ID ledger.Uint64 `json:"id"`
	// Public key corresponding to private blinding factor
	PublicBlindExcess string `json:"public_blind_excess"`
	// Public key corresponding to private nonce
	PublicNonce string `json:"public_nonce"`
	// Public partial signature
	PartSig *string `json:"part_sig"`
	// A message for other participants
	Message *string `json:"message"`
	// Signature, created with private key corresponding to 'public_blind_excess'
	MessageSig *string `json:"message_sig"`
}

// VersionCompatInfo is the versioning and compatibility info about this slate
type VersionCompatInfo struct {
	// The current version of the slate format
	Version uint16 `json:"version"`
	// Original version this slate was converted from
	OrigVersion uint16 `json:"orig_version"`
	// The grin block header version this slate is intended for
	BlockHeaderVersion uint16 `json:"block_header_version"`
}

type SavedSlate struct {
	Slate
	Blind [32]byte `json:"blind,omitempty"`
	Nonce [32]byte `json:"nonce,omitempty"`
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
