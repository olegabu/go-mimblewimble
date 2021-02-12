package multisig

import (
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-mimblewimble/wallet/multisig/vss"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/pkg/errors"
)

func FundMOfN(
	sg SecretGenerator,
	fundingAmount uint64,
	change uint64,
	fee uint64,
	asset string,
	inputs []SavedOutput,
	transactionID uuid.UUID,
	participantID string,
	participantsCount int,
	minParticipantsCount int,
) (
	slates []Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	slate, savedSlate, walletOutputs, err := Fund(sg, fundingAmount, change, fee, asset, inputs, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot Fund")
		return
	}

	slate.PartialAssetBlinds = map[string]string{participantID: hex.EncodeToString(savedSlate.PartialAssetBlind[:])}

	shares, e := vss.ShareBlind(participantsCount, minParticipantsCount, savedSlate.PartialBlind[:])
	if e != nil {
		err = errors.Wrap(e, "cannot ShareBlind")
		return
	}

	slates = make([]Slate, 0)
	for _, share := range shares {
		slate.VerifiableBlindsShares = map[string]vss.Share{participantID: share}
		slates = append(slates, *slate)
	}
	return
}

func SpendMOfN(
	sg SecretGenerator,
	spendingAmount uint64,
	fee uint64,
	asset string,
	multipartyOutput SavedOutput,
	transactionID uuid.UUID,
	participantID string,
	missingParticipantsIDs []string,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	if spendingAmount != multipartyOutput.Value {
		err = errors.New("spending amount doesn't match multiparty output value")
		return
	}

	slate, savedSlate, walletOutputs, err = Spend(sg, spendingAmount, 0, fee, asset, multipartyOutput, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot Spend")
		return
	}

	slate.VerifiableBlindsShares = make(map[string]vss.Share)
	for _, missingParticipantID := range missingParticipantsIDs {
		slate.VerifiableBlindsShares[missingParticipantID] = multipartyOutput.VerifiableBlindsShares[missingParticipantID]
	}
	return
}

func SpendMissingParty(
	sg SecretGenerator,
	spendingAmount uint64,
	fee uint64,
	asset string,
	multipartyOutput SavedOutput,
	transactionID uuid.UUID,
	missingParticipantID string,
	slates []*Slate,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	err error,
) {
	if spendingAmount != multipartyOutput.Value {
		err = errors.New("spending amount does not match multiparty output value")
		return
	}

	shares := make([]string, 0)
	for _, slate := range slates {
		shares = append(shares, slate.VerifiableBlindsShares[missingParticipantID].VerifiableShare)
	}

	secret, err := vss.OpenBlind(shares)
	if err != nil {
		err = errors.Wrap(err, "cannot OpenBlind")
		return
	}
	multipartyOutput.PartialBlind = sliceTo32Array(secret)

	partialAssetBlind, err := hex.DecodeString(multipartyOutput.PartialAssetBlinds[missingParticipantID])
	if err != nil {
		err = errors.Wrapf(err, "cannot partse asset blind of missing party with id %s", missingParticipantID)
		return
	}
	multipartyOutput.PartialAssetBlind = sliceTo32Array(partialAssetBlind)

	slate, savedSlate, _, err = Spend(sg, spendingAmount, 0, fee, asset, multipartyOutput, transactionID, missingParticipantID)
	if err != nil {
		err = errors.Wrap(err, "cannot Spend")
		return
	}
	return
}

func SignMOfN(
	slates []*Slate,
	inSavedSlate *SavedSlate,
) (
	outSlate *Slate,
	outSavedSlate *SavedSlate,
	err error,
) {
	outSavedSlate = inSavedSlate
	outSavedSlate.VerifiableBlindsShares = make(map[string]vss.Share)
	outSavedSlate.PartialAssetBlinds = make(map[string]string)
	for _, slate := range slates {
		for partyID, verifiableBlindShare := range slate.VerifiableBlindsShares {
			ok, e := vss.VerifyShare(verifiableBlindShare)
			if e != nil || !ok {
				err = errors.Errorf("verifiable blind share of participant with id %s does not correct", partyID)
				return
			}
			outSavedSlate.VerifiableBlindsShares[partyID] = verifiableBlindShare
		}

		for partyID, partialAssetBlinds := range slate.PartialAssetBlinds {
			outSavedSlate.PartialAssetBlinds[partyID] = partialAssetBlinds
		}

		slate.VerifiableBlindsShares = nil
		slate.PartialAssetBlinds = nil
	}

	outSlate, err = Sign(slates, inSavedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot Sign")
		return
	}
	return
}

func AggregateMOfN(
	slates []*Slate,
	savedSlate *SavedSlate,
) (
	transaction *ledger.Transaction,
	savedTransaction SavedTransaction,
	multipartyOutput *SavedOutput,
	err error,
) {
	transaction, savedTransaction, multipartyOutput, err = Aggregate(slates, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot Aggregate")
		return
	}

	if multipartyOutput != nil {
		multipartyOutput.VerifiableBlindsShares = savedSlate.VerifiableBlindsShares
		multipartyOutput.PartialAssetBlinds = savedSlate.PartialAssetBlinds
	}
	return
}
