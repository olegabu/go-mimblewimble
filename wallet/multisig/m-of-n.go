package multisig

import (
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
	slates []*Slate,
	savedSlate *SavedSlate,
	walletOutputs []SavedOutput,
	err error,
) {
	slate, savedSlate, walletOutputs, err := Fund(sg, fundingAmount, change, fee, asset, inputs, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot InitMultisigTransaction")
		return
	}

	slate.PartialAssetBlinds = map[string][32]byte{participantID: savedSlate.PartialAssetBlind}

	shares, e := vss.ShareBlind(participantsCount, minParticipantsCount, savedSlate.PartialBlind[:])
	if e != nil {
		err = errors.Wrap(e, "cannot ShareBlind")
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
		err = errors.New("spending amount does not match to multiparty output value")
		return
	}

	slate, savedSlate, walletOutputs, err = Spend(sg, spendingAmount, 0, fee, asset, multipartyOutput, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot InitMultisigTransaction")
		return
	}

	slate.VerifiableBlindsShares = make(map[string]vss.Share)
	slate.PartialAssetBlinds = make(map[string][32]byte)
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
		err = errors.New("spending amount does not match to multiparty output value")
		return
	}

	shares := make([]string, 0)
	for _, slate := range slates {
		shares = append(shares, slate.VerifiableBlindsShares[missingParticipantID].VerifiableShare)
	}

	secret, e := vss.OpenBlind(shares)
	if e != nil {
		err = errors.Wrap(e, "cannot openBlind")
		return
	}
	var blind [32]byte
	copy(blind[:], secret)
	multipartyOutput.PartialBlind = &blind

	partialAssetBlind := multipartyOutput.PartialAssetBlinds[missingParticipantID]
	multipartyOutput.PartialAssetBlind = &partialAssetBlind

	slate, savedSlate, _, err = Spend(sg, spendingAmount, 0, fee, asset, multipartyOutput, transactionID, missingParticipantID)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
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
	outSlate, err = Sign(slates, inSavedSlate)
	if err != nil {
		err = errors.Wrap(err, "cannot signMultipartyTransaction")
		return
	}

	outSavedSlate = inSavedSlate
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
		err = errors.Wrap(err, "cannot aggregateFundingTransaction")
		return
	}

	if multipartyOutput != nil {
		multipartyOutput.VerifiableBlindsShares = savedSlate.VerifiableBlindsShares
		multipartyOutput.PartialAssetBlinds = savedSlate.PartialAssetBlinds
	}
	return
}
