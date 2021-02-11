package multisig

import (
	"encoding/hex"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/wallet/types"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func createPartialSignature(context *secp256k1.Context, slate *Slate, savedSlate *SavedSlate) (partialSignatureString string, err error) {
	aggregatedPublicKey, aggregatedPublicNonce, err := getAggregatedPublicKeyAndNonce(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot get aggregated public key and aggregated public nonce")
		return
	}

	msg := ledger.KernelSignatureMessage(savedSlate.Transaction.Body.Kernels[0])

	var privateKey [32]byte
	if newMultipartyUtxoIsNeccessary(slate) {
		assetBlind := savedSlate.PartialAssetBlind
		blind := savedSlate.PartialBlind

		value := getMultipartyOutputValue(slate)
		blindValueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind[:], blind[:])
		if e != nil {
			err = errors.Wrap(e, "cannot compute: blind + value * assetBlind")
			return
		}

		privateKey, e = secp256k1.BlindSum(context, [][]byte{blindValueAssetBlind[:], savedSlate.ExcessBlind[:]}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot compute private key: excess + blind + value * assetBlind")
			return
		}
	} else {
		privateKey, err = secp256k1.BlindSum(context, [][]byte{savedSlate.ExcessBlind[:]}, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot compute private key: excess")
			return
		}
	}

	partialSignature, err := secp256k1.AggsigSignPartial(context, privateKey[:], savedSlate.Nonce[:], aggregatedPublicNonce, aggregatedPublicKey, msg)
	if err != nil {
		err = errors.Wrap(err, "cannot create partial signature")
		return
	}
	partialSignatureBytes := secp256k1.AggsigSignaturePartialSerialize(&partialSignature)
	partialSignatureString = hex.EncodeToString(partialSignatureBytes[:])
	return
}

func aggregatePartialSignatures(context *secp256k1.Context, slate *Slate) (signature secp256k1.AggsigSignature, err error) {
	aggregatedPublicKey, aggregatedPublicNonce, err := getAggregatedPublicKeyAndNonce(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot get aggregated public key and aggregated public nonce")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	partialSignatures := make([]*secp256k1.AggsigSignaturePartial, 0)
	for partyID, party := range slate.ParticipantData {
		partialSignatureBytes, e := hex.DecodeString(*party.PartSig)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse partial signature of participant with id %s", partyID)
			return
		}

		partialSignature, e := secp256k1.AggsigSignaturePartialParse(partialSignatureBytes)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse partial signature of participant with id %s", partyID)
			return
		}

		publicBlindExcess, e := secp256k1.CommitmentFromString(party.PublicBlindExcess)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse public excess of participant with id %s", partyID)
			return
		}

		var partialPublicKeyCommit *secp256k1.Commitment
		if newMultipartyUtxoIsNeccessary(slate) && party.IsMultisigFundOwner {
			publicBlind, e := secp256k1.CommitmentFromString(party.PublicBlind)
			if e != nil {
				err = errors.Wrapf(e, "cannot parse public blind of participant with id %s", partyID)
				return
			}

			assetBlind, e := hex.DecodeString(party.AssetBlind)
			if e != nil {
				err = errors.Wrapf(e, "cannot parse asset blind of participant with id %s", partyID)
				return
			}

			value := getMultipartyOutputValue(slate)
			valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind, new([32]byte)[:])
			if e != nil {
				err = errors.Wrapf(e, "cannot compute value * assetBlind of participant with id %s", partyID)
				return
			}

			publicValueAssetBlind, e := secp256k1.Commit(context, valueAssetBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
			if e != nil {
				err = errors.Wrapf(e, "cannot compute (value * assetBlind) * G of participant with id %s", partyID)
				return
			}

			publicBlindValueAssetBlind, e := secp256k1.CommitSum(context, []*secp256k1.Commitment{publicBlind, publicValueAssetBlind}, nil)
			if e != nil {
				err = errors.Wrapf(e, "cannot compute (blind + value * assetBlind) * G of participant with id %s", partyID)
				return
			}

			partialPublicKeyCommit, e = secp256k1.CommitSum(context, []*secp256k1.Commitment{publicBlindExcess, publicBlindValueAssetBlind}, nil)
			if e != nil {
				err = errors.Wrapf(e, "cannot compute public key: PublicExcess + (blind + value * assetBlind) * G of participant with id %s", partyID)
				return
			}
		} else {
			partialPublicKeyCommit, e = secp256k1.CommitSum(context, []*secp256k1.Commitment{publicBlindExcess}, nil)
			if e != nil {
				err = errors.Wrapf(e, "cannot compute public key: PublicExcess of participant with id %s", partyID)
				return
			}
		}

		partialPublicKey, e := secp256k1.CommitmentToPublicKey(context, partialPublicKeyCommit)
		if e != nil {
			err = errors.Wrapf(e, "cannot convert public key of participant with id %s from Commitment to PublicKey", partyID)
			return
		}

		e = secp256k1.AggsigVerifyPartial(context, &partialSignature, aggregatedPublicNonce, partialPublicKey, aggregatedPublicKey, msg)
		if e != nil {
			err = errors.Wrap(e, "partial signature of participant with id "+partyID+"is invalid")
			return
		}

		partialSignatures = append(partialSignatures, &partialSignature)
	}

	signature, err = secp256k1.AggsigAddSignaturesSingle(context, partialSignatures, aggregatedPublicNonce)
	if err != nil {
		err = errors.Wrap(err, "cannot aggregate partial signatures")
		return
	}

	err = secp256k1.AggsigVerifySingle(context, &signature, msg, nil, aggregatedPublicKey, aggregatedPublicKey, nil, false)
	if err != nil {
		err = errors.Wrap(err, "aggregated signature doesn't match the aggregated public key")
		return
	}
	return
}

func getAggregatedPublicKeyAndNonce(context *secp256k1.Context, slate *Slate) (aggPublicKey *secp256k1.PublicKey, aggPublicNonce *secp256k1.PublicKey, err error) {
	var publicBlinds, publicBlindExcesses, publicNonces, publicValueAssetBlinds []*secp256k1.Commitment
	for partyID, party := range slate.ParticipantData {
		publicBlindExcess, e := secp256k1.CommitmentFromString(party.PublicBlindExcess)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse public excess of participant with id %s", partyID)
			return
		}
		publicBlindExcesses = append(publicBlindExcesses, publicBlindExcess)

		publicNonce, e := secp256k1.CommitmentFromString(party.PublicNonce)
		if e != nil {
			err = errors.Wrapf(e, "cannot parse public nonce of participant with id %s", partyID)
			return
		}
		publicNonces = append(publicNonces, publicNonce)

		if newMultipartyUtxoIsNeccessary(slate) && party.IsMultisigFundOwner {
			publicBlind, e := secp256k1.CommitmentFromString(party.PublicBlind)
			if e != nil {
				err = errors.Wrapf(e, "cannot parse public blind of participant with id %s", partyID)
				return
			}
			publicBlinds = append(publicBlinds, publicBlind)

			assetBlind, e := hex.DecodeString(party.AssetBlind)
			if e != nil {
				err = errors.Wrapf(e, "cannot parse asset blind of participant with id %s", partyID)
				return
			}

			value := getMultipartyOutputValue(slate)
			valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind, new([32]byte)[:])
			if e != nil {
				err = errors.Wrapf(e, "cannot compute value * assetBlind of participant with id %s", partyID)
				return
			}

			publicValueAssetBlind, e := secp256k1.Commit(context, valueAssetBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
			if e != nil {
				err = errors.Wrapf(e, "cannot compute (value * assetBlind) * G of participant with id %s", partyID)
				return
			}
			publicValueAssetBlinds = append(publicValueAssetBlinds, publicValueAssetBlind)
		}
	}

	publicKeyCommit, err := secp256k1.CommitSum(context, append(append(publicBlinds, publicValueAssetBlinds...), publicBlindExcesses...), nil)
	if err != nil {
		err = errors.Wrap(err, "cannot compute aggregated public key: SumOfPublicBlinds + SumOfPublicValueAssetBlinds + SumOfPublicExcesses")
		return
	}

	aggPublicKey, err = secp256k1.CommitmentToPublicKey(context, publicKeyCommit)
	if err != nil {
		err = errors.Wrap(err, "cannot convert aggregated public key from Commitment to PublicKey")
		return
	}

	publicNonceCommit, err := secp256k1.CommitSum(context, publicNonces, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot compute aggregated public nonce")
		return
	}

	aggPublicNonce, err = secp256k1.CommitmentToPublicKey(context, publicNonceCommit)
	if err != nil {
		err = errors.Wrap(err, "cannot convert aggregated public nonce from Commitment to PublicKey")
		return
	}
	return
}
