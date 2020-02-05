package multiasset

import (
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/olegabu/go-secp256k1-zkp"
)

type Asset struct {
	id        string
	generator secp256k1.Generator
}
type publicOutput struct {
	Input
	Proof           string `json:"proof"`
	SurjectionProof string `json:"surjection_proof"`
}

type privateOutput struct {
	publicOutput
	ValueBlind [32]byte            `json:"value_blind,omitempty"`
	AssetBlind [32]byte            `json:"value_blind,omitempty"`
	Value      uint64              `json:"value,omitempty"`
	Status     wallet.OutputStatus `json:"status,omitempty"`
	Asset      Asset               `json:"asset,omitempty"`
}

type TransactionBody struct {
	Inputs  []Input         `json:"inputs"`
	Outputs []publicOutput  `json:"outputs"`
	Kernels []core.TxKernel `json:"kernels"`
}

type LedgerTransaction struct {
	Offset string `json:"offset"`
	// The transaction body - inputs/outputs/kernels
	Body TransactionBody `json:"body"`
	ID   uuid.UUID       `json:"id,omitempty"`
}
type WalletTransaction struct {
	LedgerTransaction
	Status wallet.TransactionStatus `json:"status,omitempty"`
	Asset  string                   `json:"asset,omitempty"`
}

type Commitment struct {
	ValueCommitment string `json:"value_commitment"`
	AssetCommitment string `json:"asset_commitment"`
}

type Input struct {
	// The features of the output being spent.
	// We will check maturity for coinbase output.
	Features core.OutputFeatures `json:"features"`
	// The commit referencing the output being spent.
	Commit Commitment `json:"commit"`
}
type GrinSlate struct {
	// Versioning info
	VersionInfo libwallet.VersionCompatInfo `json:"version_info"`
	// The number of participants intended to take part in this transaction
	NumParticipants uint `json:"num_participants"`
	// Unique transaction ID, selected by sender
	ID uuid.UUID `json:"id"`
	// The core transaction data:
	// inputs, outputs, kernels, kernel offset
	Transaction LedgerTransaction `json:"tx"`
	// base amount (excluding fee)
	Amount core.Uint64 `json:"amount"`
	// fee amount
	Fee core.Uint64 `json:"fee"`
	// Block height for the transaction
	Height core.Uint64 `json:"height"`
	// Lock height
	LockHeight core.Uint64 `json:"lock_height"`
	// TTL, the block height at which wallets
	// should refuse to process the transaction and unlock all
	// associated outputs
	TTLCutoffHeight *core.Uint64 `json:"ttl_cutoff_height"`
	// Participant data, each participant in the transaction will
	// insert their public data here. For now, 0 is sender and 1
	// is receiver, though this will change for multi-party
	ParticipantData []libwallet.ParticipantData `json:"participant_data"`
	// Payment Proof
	PaymentProof *libwallet.PaymentInfo `json:"payment_proof"`
}
type Slate struct {
	GrinSlate
	Asset  string             `json:"asset,omitempty"`
	Status wallet.SlateStatus `json:"status,omitempty"`
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

type AssetBalance struct {
	asset  Asset
	amount uint64
}

//type Transaction struct {
//	ledger.Transaction
//	Status TransactionStatus `json:"status,omitempty"`
//	Asset  string            `json:"asset,omitempty"`
//}
