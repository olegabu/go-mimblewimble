package multisigwallet

import (
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/multisigwallet/vss"
	"github.com/pkg/errors"
)

func (t *Wallet) initMofNFundingMultipartyTransaction(
	inputs []SavedOutput,
	change uint64,
	fee uint64,
	transactionID uuid.UUID,
	participantID string,
	participantsCount int,
	minParticipantsCount int,
) (
	slates []*Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	slate, savedSlate, walletOutputs, err := t.initMultipartyTransaction(inputs, change, 0, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}

	slate.PartialAssetBlinds = make(map[string][32]byte)
	slate.PartialAssetBlinds[participantID] = savedSlate.AssetBlind

	shares, e := vss.ShareBlind(participantsCount, minParticipantsCount, savedSlate.Blind[:])
	if e != nil {
		err = errors.Wrap(e, "cannot generateAndShareBlinds")
		return
	}

	slates = make([]*Slate, 0)
	for _, share := range shares {
		curSlate := &Slate{}
		*curSlate = *slate
		curSlate.VerifiableBlindsShares = make(map[string]vss.Share)
		curSlate.VerifiableBlindsShares[participantID] = share
		slates = append(slates, curSlate)
	}
	return
}

func (t *Wallet) initMofNSpendingMultipartyTransaction(
	inputs []SavedOutput,
	change uint64,
	fee uint64,
	transactionID uuid.UUID,
	participantID string,
	missingParticipantsIDs []string,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	slate, savedSlate, walletOutputs, err = t.initMultipartyTransaction(inputs, change, 0, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}

	multipartyOutput := inputs[0]
	slate.VerifiableBlindsShares = make(map[string]vss.Share)
	slate.PartialAssetBlinds = make(map[string][32]byte)
	for _, missingParticipantID := range missingParticipantsIDs {
		slate.VerifiableBlindsShares[missingParticipantID] = multipartyOutput.VerifiableBlindsShares[missingParticipantID]
		slate.PartialAssetBlinds[missingParticipantID] = multipartyOutput.PartialAssetBlinds[missingParticipantID]
	}
	return
}

func (t *Wallet) signMofNMultipartyTransaction(
	slates []*Slate,
	inSavedSlate *SavedSlate,
) (
	outSlate *Slate,
	outSavedSlate *SavedSlate,
	err error,
) {
	outSavedSlate = new(SavedSlate)
	*outSavedSlate = *inSavedSlate
	outSavedSlate.VerifiableBlindsShares = make(map[string]vss.Share)
	outSavedSlate.PartialAssetBlinds = make(map[string][32]byte)
	for _, slate := range slates {
		for participantID, verifiableBlindShare := range slate.VerifiableBlindsShares {
			ok, e := vss.VerifyShare(verifiableBlindShare)
			if e != nil || !ok {
				err = errors.New("verifiable blinds shares does not correct")
				return
			}
			outSavedSlate.VerifiableBlindsShares[participantID] = verifiableBlindShare
		}

		for participantID, partialAssetBlinds := range slate.PartialAssetBlinds {
			outSavedSlate.PartialAssetBlinds[participantID] = partialAssetBlinds
		}
	}

	outSlate, err = t.signMultipartyTransaction(slates, inSavedSlate)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot signMultipartyTransaction")
	}
	return
}

func (t *Wallet) constructMissingPartySlate(
	slates []*Slate,
	multipartyOutput SavedOutput,
	fee uint64,
	transactionID uuid.UUID,
	missingParticipantID string,
) (
	slate *Slate,
	savedSlate *SavedSlate,
	err error,
) {
	shares := make([]string, 0)
	for _, slate := range slates {
		shares = append(shares, slate.VerifiableBlindsShares[missingParticipantID].VerifiableShare)
	}

	blind, e := vss.OpenBlind(shares)
	if e != nil {
		err = errors.Wrap(e, "cannot openBlind")
		return
	}

	multipartyOutput.PartialAssetBlind = multipartyOutput.PartialAssetBlinds[missingParticipantID]
	copy(multipartyOutput.Blind[:], blind)
	slate, savedSlate, _, err = t.initMultipartyTransaction([]SavedOutput{multipartyOutput}, 0, 0, transactionID, missingParticipantID)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}
	return
}
