package multisigwallet

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-mimblewimble/multisigwallet/bulletproof"
	"github.com/olegabu/go-mimblewimble/multisigwallet/vss"
)

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

type SlateInput struct {
	ledger.Input
	//Asset      string       `json:"asset,omitempty"`
	AssetTag     string `json:"asset_tag"`
	AssetBlind   string `json:"asset_blind"`
	IsMultiparty bool   `json:"multiparty"`
}

type SlateOutput struct {
	ledger.Output
	//Asset      string       `json:"asset,omitempty"`
	AssetTag     string `json:"asset_tag"`
	AssetBlind   string `json:"asset_blind"`
	IsMultiparty bool   `json:"multiparty"`
}

type SavedOutput struct {
	SlateOutput
	Blind             [32]byte     `json:"blind,omitempty"`
	PartialAssetBlind [32]byte     `json:"partial_asset_blind,omitempty"`
	Value             uint64       `json:"value"`
	Asset             string       `json:"asset,omitempty"`
	Status            OutputStatus `json:"status,omitempty"`

	VerifiableBlindsShares map[string]vss.Share `json:"verifiable_blinds_shares,omitempty"`
	PartialAssetBlinds     map[string][32]byte  `json:"partial_asset_blinds,omitempty"`
}

type OutputStatus int

const (
	OutputUnconfirmed = iota
	OutputConfirmed
	OutputLocked
	OutputSpent
	OutputCanceled
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
	case OutputCanceled:
		return "Canceled"
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
	Transaction SlateTransaction `json:"tx"`
	// base amount (excluding fee)
	Amount ledger.Uint64 `json:"amount"`
	// fee amount
	Fee ledger.Uint64 `json:"fee"`
	// Block height for the transaction
	Height ledger.Uint64 `json:"height"`
	// Lock height
	LockHeight ledger.Uint64 `json:"lock_height"`
	// Participant data, each participant in the transaction will
	// insert their public data here.
	ParticipantData map[string]*ParticipantData `json:"participant_data"`

	Asset         string        `json:"asset,omitempty"`
	ReceiveAmount ledger.Uint64 `json:"receive_amount,omitempty"`
	ReceiveAsset  string        `json:"receive_asset,omitempty"`

	// Verifiable blind's shares for m-of-n multiparty outputs
	VerifiableBlindsShares map[string]vss.Share `json:"verifiable_blinds_shares,omitempty"`
	PartialAssetBlinds     map[string][32]byte  `json:"partial_asset_blinds,omitempty"`
}

// ParticipantData is a public data for each participant in the slate
type ParticipantData struct {
	// Value
	Value ledger.Uint64 `json:"value"`
	// Public key corresponding to blinding factor
	PublicBlind string `json:"public_blind"`
	// Asset blinding factor
	AssetBlind string `json:"asset_blind"`
	// Public key corresponding to private excess blinding factor
	PublicBlindExcess string `json:"public_blind_excess"`
	// Public key corresponding to private nonce
	PublicNonce string `json:"public_nonce"`
	// Public partial signature
	PartSig *string `json:"part_sig"`
	// A message for other participants
	Message *string `json:"message"`
	// Signature, created with private key corresponding to 'public_blind_excess'
	MessageSig *string `json:"message_sig"`
	// Shared data for Bulletproof MPC
	BulletproofsShare *bulletproof.Share `json:"bulletproofs_share"`
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
	Blind         [32]byte `json:"blind_index,omitempty"`
	AssetBlind    [32]byte `json:"asset_blind_index,omitempty"`
	ExcessBlind   [32]byte `json:"excess_blind,omitempty"`
	Nonce         [32]byte `json:"nonce,omitempty"`
	ParticipantID string   `json:"participant_id,omitempty"`
}

type SlateTransactionBody struct {
	Inputs  []SlateInput      `json:"inputs"`
	Outputs []SlateOutput     `json:"outputs"`
	Kernels []ledger.TxKernel `json:"kernels"`
}

type SlateTransaction struct {
	Offset string               `json:"offset"`
	Body   SlateTransactionBody `json:"body"`
	ID     uuid.UUID            `json:"id,omitempty"`
}

type SavedTransaction struct {
	ledger.Transaction
	Status TransactionStatus `json:"status,omitempty"`
}

type TransactionStatus int

const (
	TransactionUnconfirmed = iota
	TransactionConfirmed
	TransactionCanceled
)

func (t TransactionStatus) String() string {
	switch t {
	case TransactionUnconfirmed:
		return "Unconfirmed"
	case TransactionConfirmed:
		return "Confirmed"
	case TransactionCanceled:
		return "Canceled"
	default:
		return fmt.Sprintf("%d", int(t))
	}
}
