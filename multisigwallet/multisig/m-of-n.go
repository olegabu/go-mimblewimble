package multisig

import (
	"github.com/google/uuid"
	"github.com/olegabu/go-mimblewimble/multisigwallet/multisig/vss"
	. "github.com/olegabu/go-mimblewimble/multisigwallet/types"
	"github.com/pkg/errors"
)

func InitMOfNFundingMultipartyTransaction(
	wallet Wallet,
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
	var amount uint64
	for _, input := range inputs {
		amount += input.Value
	}
	amount -= change

	slate, savedSlate, walletOutputs, err := InitMultipartyTransaction(wallet, amount, inputs, change, 0, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}

	slate.PartialAssetBlinds = make(map[string][32]byte)
	slate.PartialAssetBlinds[participantID] = savedSlate.PartialAssetBlind

	shares, e := vss.ShareBlind(participantsCount, minParticipantsCount, savedSlate.PartialBlind[:])
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

func InitMOfNSpendingMultipartyTransaction(
	wallet Wallet,
	multipartyOutput SavedOutput,
	amount uint64,
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
	slate, savedSlate, walletOutputs, err = InitMultipartyTransaction(wallet, amount, []SavedOutput{multipartyOutput}, 0, 0, transactionID, participantID)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}

	slate.VerifiableBlindsShares = make(map[string]vss.Share)
	slate.PartialAssetBlinds = make(map[string][32]byte)
	for _, missingParticipantID := range missingParticipantsIDs {
		slate.VerifiableBlindsShares[missingParticipantID] = multipartyOutput.VerifiableBlindsShares[missingParticipantID]
	}
	return
}

func SignMOfNMultipartyTransaction(
	wallet Wallet,
	slates []*Slate,
	inSavedSlate *SavedSlate,
) (
	outSlate *Slate,
	outSavedSlate *SavedSlate,
	err error,
) {
	outSlate, err = SignMultipartyTransaction(wallet, slates, inSavedSlate)
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

func ConstructMissingPartySlate(
	wallet Wallet,
	slates []*Slate,
	multipartyOutput SavedOutput,
	amount uint64,
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

	slate, savedSlate, _, err = InitMultipartyTransaction(wallet, amount, []SavedOutput{multipartyOutput}, 0, 0, transactionID, missingParticipantID)
	if err != nil {
		err = errors.Wrap(err, "cannot initMultipartyTransaction")
		return
	}
	return
}
