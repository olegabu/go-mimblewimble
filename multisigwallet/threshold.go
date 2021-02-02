package multisigwallet

import (
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
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
	precalculatedBlindsCount int,
) (
	slates []*Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	slate, savedSlate, walletOutputs, err := t.initMultipartyTransaction(inputs, change, 0, transactionID, participantID, nil, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}

	blinds := [][]byte{savedSlate.Blind[:]}
	reservedBlindIndexes := []uint32{}
	reservedAssetBlindIndexes := []uint32{}

	slate.PartialAssetBlinds = make(map[string][][32]byte)
	slate.PartialAssetBlinds[participantID] = append(slate.PartialAssetBlinds[participantID], savedSlate.AssetBlind)
	for i := 0; i < precalculatedBlindsCount; i++ {
		precalculatedBlind, precalculatedBlindIndex, e := t.newSecret()
		if e != nil {
			err = errors.Wrap(e, "cannot newSecret")
			return
		}
		blinds = append(blinds, precalculatedBlind[:])
		reservedBlindIndexes = append(reservedBlindIndexes, precalculatedBlindIndex)

		precalculatedAssetBlind, precalculatedAssetBlindIndex, e := t.newSecret()
		if e != nil {
			err = errors.Wrap(e, "cannot newSecret")
			return
		}
		reservedAssetBlindIndexes = append(reservedAssetBlindIndexes, precalculatedAssetBlindIndex)
		slate.PartialAssetBlinds[participantID] = append(slate.PartialAssetBlinds[participantID], precalculatedAssetBlind)
	}

	shares, e := t.generateAndShareBlinds(participantsCount, minParticipantsCount, blinds)
	if e != nil {
		err = errors.Wrap(e, "cannot generateAndShareBlinds")
		return
	}

	slates = make([]*Slate, 0)
	for _, share := range shares {
		curSlate := &Slate{}
		*curSlate = *slate
		curSlate.VerifiableBlindsShares = make(map[string][]VerifiableShare)
		curSlate.VerifiableBlindsShares[participantID] = share
		slates = append(slates, curSlate)
	}

	savedSlate.ReservedBlindIndexes = reservedBlindIndexes
	savedSlate.ReservedAssetBlindIndexes = reservedAssetBlindIndexes

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
	multipartyOutput := inputs[0]
	if len(multipartyOutput.ReservedBlindIndexes) == 0 {
		err = errors.Wrap(err, "cannot get reserved blind index")
		return
	}

	reservedBlindIndex := multipartyOutput.ReservedBlindIndexes[0]
	reservedBlind, err := t.secret(reservedBlindIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot get secret")
		return
	}

	reservedAssetBlindIndex := multipartyOutput.ReservedAssetBlindIndexes[0]
	reservedAssetBlind, err := t.secret(reservedAssetBlindIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot get secret")
		return
	}

	slate, savedSlate, walletOutputs, err = t.initMultipartyTransaction(inputs, change, 0, transactionID, participantID, &reservedBlind, &reservedAssetBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}

	slate.VerifiableBlindsShares = make(map[string][]VerifiableShare)
	slate.PartialAssetBlinds = make(map[string][][32]byte)
	for _, missingParticipantID := range missingParticipantsIDs {
		slate.VerifiableBlindsShares[missingParticipantID] = multipartyOutput.VerifiableBlindsShares[missingParticipantID][:2]
		slate.PartialAssetBlinds[missingParticipantID] = multipartyOutput.PartialAssetBlinds[missingParticipantID][:2]
	}
	savedSlate.ReservedBlindIndexes = multipartyOutput.ReservedBlindIndexes[1:]
	savedSlate.ReservedAssetBlindIndexes = multipartyOutput.ReservedAssetBlindIndexes[1:]
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
	outSavedSlate.VerifiableBlindsShares = make(map[string][]VerifiableShare)
	outSavedSlate.PartialAssetBlinds = make(map[string][][32]byte)
	for _, slate := range slates {
		for participantID, verifiableBlindsShares := range slate.VerifiableBlindsShares {
			ok, e := t.verifyShares(verifiableBlindsShares)
			if e != nil || !ok {
				err = errors.New("verifiable blinds shares does not correct")
				return
			}
			outSavedSlate.VerifiableBlindsShares[participantID] = verifiableBlindsShares
		}

		for participantID, partialAssetBlinds := range slate.PartialAssetBlinds {
			outSavedSlate.PartialAssetBlinds[participantID] = partialAssetBlinds
		}
	}

	outSlate, err = t.signMultipartyTransaction(slates, inSavedSlate)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot signMultipartyTransaction")
	}

	outSlate.VerifiableBlindsShares = outSavedSlate.VerifiableBlindsShares
	outSlate.PartialAssetBlinds = outSavedSlate.PartialAssetBlinds
	return
}

func (t *Wallet) aggregateMofNMultipartyTransaction(
	slates []*Slate,
	savedSlate *SavedSlate,
) (
	transaction *ledger.Transaction,
	savedTransaction SavedTransaction,
	multipartyOutput *SavedOutput,
	err error,
) {
	transaction, savedTransaction, multipartyOutput, err = t.aggregateMultipartyTransaction(slates, savedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregateFundingTransaction")
		return
	}

	multipartyOutput.ReservedBlindIndexes = savedSlate.ReservedBlindIndexes
	multipartyOutput.ReservedAssetBlindIndexes = savedSlate.ReservedAssetBlindIndexes
	multipartyOutput.VerifiableBlindsShares = savedSlate.VerifiableBlindsShares
	multipartyOutput.PartialAssetBlinds = savedSlate.PartialAssetBlinds

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
	// Восстанавливаем текущий и будущий blind отсутствующей стороны
	blinds := make([][32]byte, 2)
	for i := 0; i < 2; i++ {
		shares := make([]string, 0)
		for _, slate := range slates {
			shares = append(shares, slate.VerifiableBlindsShares[missingParticipantID][i].VerifiableShare)
		}

		blind, e := t.openBlind(shares)
		if e != nil {
			err = errors.Wrap(e, "cannot openBlind")
			return
		}
		copy(blinds[i][:], blind)
	}

	multipartyOutput.PartialAssetBlind = multipartyOutput.PartialAssetBlinds[missingParticipantID][0]
	multipartyOutput.Blind = blinds[0]
	assetBlind := multipartyOutput.PartialAssetBlinds[missingParticipantID][1]
	slate, savedSlate, _, err = t.initMultipartyTransaction([]SavedOutput{multipartyOutput}, 0, 0, transactionID, missingParticipantID, &blinds[1], &assetBlind)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}

	return
}
