package multiasset

import (
	"github.com/blockcypher/libgrin/core"
	"github.com/blockcypher/libgrin/libwallet"
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/wallet"
	"golang.org/x/crypto/blake2b"
)

type Asset struct {
	Id   [32]byte
	name string
}

func newAsset(name string) Asset {
	hash, _ := blake2b.New256(nil)
	hash.Write([]byte(name))
	var id [32]byte
	copy(id[:], hash.Sum(nil)[:32])
	return Asset{
		Id:   id,
		name: name,
	}
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

type TxKernel struct {
	// Options for a kernel's structure or use
	Features core.KernelFeatures `json:"features"`
	// Fee originally included in the transaction this proof is for.
	Fee AssetBalance `json:"fee"`
	// This kernel is not valid earlier than lock_height blocks
	// The max lock_height of all *inputs* to this transaction
	LockHeight core.Uint64 `json:"lock_height"`
	// Remainder of the sum of all transaction commitments. If the transaction
	// is well formed, amounts components should sum to zero and the excess
	// is hence a valid public key.
	Excess string `json:"excess"`
	// The signature proving the excess is a valid public key, which signs
	// the transaction fee.
	ExcessSig string `json:"excess_sig"`
}
type TransactionBody struct {
	Inputs  []Input        `json:"inputs"`
	Outputs []publicOutput `json:"outputs"`
	Kernels []TxKernel     `json:"kernels"`
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
type publicSlate struct {
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
	Amount []AssetBalance `json:"amount"`
	// fee amount
	Fee AssetBalance `json:"fee"`
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
	publicSlate
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
