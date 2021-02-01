package multisigwallet

import (
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/pkg/errors"
)

func (t *Wallet) initMofNMultipartyTransaction(
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
	slate, savedSlate, walletOutputs, err := t.initMultipartyTransaction(inputs, change, 0, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot NewMultipartySlate")
		return
	}

	blind, err := t.secret(savedSlate.BlindIndex)
	if err != nil {
		err = errors.Wrap(err, "cannot secret")
		return
	}

	blinds := [][]byte{blind[:]}
	reservedBlindsIndexes := []uint32{savedSlate.BlindIndex}

	for i := 1; i < precalculatedBlindsCount; i++ {
		precalculatedBlind, precalculatedBlindIndex, e := t.newSecret()
		if e != nil {
			err = errors.Wrap(e, "cannot newSecret")
			return
		}
		blinds = append(blinds, precalculatedBlind[:])
		reservedBlindsIndexes = append(reservedBlindsIndexes, precalculatedBlindIndex)
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

	//savedSlate.VerifiableBlindsShares = slates[0].VerifiableBlindsShares
	savedSlate.ReservedBlindIndexes = reservedBlindsIndexes

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
	for _, slate := range slates {
		for participantID, verifiableBlindsShares := range slate.VerifiableBlindsShares {
			ok, e := t.verifyShares(verifiableBlindsShares)
			if e != nil || !ok {
				err = errors.New("verifiable blinds shares does not correct")
				return
			}
			outSavedSlate.VerifiableBlindsShares[participantID] = verifiableBlindsShares
		}
	}

	outSlate, err = t.signMultipartyTransaction(slates, inSavedSlate)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot signMultipartyTransaction")
	}
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
	multipartyOutput.VerifiableBlindsShares = savedSlate.VerifiableBlindsShares
	return
}
