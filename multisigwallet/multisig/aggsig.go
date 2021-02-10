package multisig

import (
	"encoding/hex"

	"github.com/olegabu/go-mimblewimble/ledger"
	. "github.com/olegabu/go-mimblewimble/multisigwallet/types"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func createPartialSignature(context *secp256k1.Context, slate *Slate, savedSlate *SavedSlate) (partialSignatureString string, err error) {
	aggregatedPublicKey, aggregatedPublicNonce, err := getAggregatedPublicKeyAndNonce(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot getAggregatedPublicKeyAndNonce")
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
			err = errors.Wrap(e, "cannot BlindValueGeneratorBlindSum")
			return
		}

		privateKey, e = secp256k1.BlindSum(context, [][]byte{blindValueAssetBlind[:], savedSlate.ExcessBlind[:]}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot compute private key")
			return
		}
	} else {
		privateKey, err = secp256k1.BlindSum(context, [][]byte{savedSlate.ExcessBlind[:]}, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot compute private key")
			return
		}
	}

	partialSignature, err := secp256k1.AggsigSignPartial(context, privateKey[:], savedSlate.Nonce[:], aggregatedPublicNonce, aggregatedPublicKey, msg)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate receiver's partial signature")
		return
	}
	partialSignatureBytes := secp256k1.AggsigSignaturePartialSerialize(&partialSignature)
	partialSignatureString = hex.EncodeToString(partialSignatureBytes[:])
	return
}

func aggregatePartialSignatures(context *secp256k1.Context, slate *Slate) (signature secp256k1.AggsigSignature, err error) {
	aggregatedPublicKey, aggregatedPublicNonce, err := getAggregatedPublicKeyAndNonce(context, slate)
	if err != nil {
		err = errors.Wrap(err, "cannot getAggregatedPublicKeyAndNonce")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	partialSignatures := make([]*secp256k1.AggsigSignaturePartial, 0)
	for _, party := range slate.ParticipantData {
		partialSignatureBytes, e := hex.DecodeString(*party.PartSig)
		if e != nil {
			err = errors.Wrap(e, "cannot decode receiverPartSigBytes from hex")
			return
		}

		partialSignature, e := secp256k1.AggsigSignaturePartialParse(partialSignatureBytes)
		if e != nil {
			err = errors.Wrap(e, "cannot parse receiverPartialSig from bytes")
			return
		}

		publicBlindExcess, e := secp256k1.CommitmentFromString(party.PublicBlindExcess)
		if e != nil {
			err = errors.Wrap(e, "cannot parse public blind excess")
			return
		}

		var partialPublicKeyCommit *secp256k1.Commitment
		if newMultipartyUtxoIsNeccessary(slate) && party.IsMultisigFundOwner {
			publicBlind, e := secp256k1.CommitmentFromString(party.PublicBlind)
			if e != nil {
				err = errors.Wrap(e, "cannot parse public blind")
				return
			}

			assetBlind, e := hex.DecodeString(party.AssetBlind)
			if e != nil {
				err = errors.Wrap(e, "cannot parse asset blind")
				return
			}

			value := getMultipartyOutputValue(slate)
			valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind, new([32]byte)[:])
			if e != nil {
				err = errors.Wrap(e, "cannot BlindValueGeneratorBlindSum")
				return
			}

			publicValueAssetBlind, e := secp256k1.Commit(context, valueAssetBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
			if e != nil {
				err = errors.Wrap(e, "cannot Commit")
				return
			}

			publicBlindValueAssetBlind, e := secp256k1.CommitSum(context, []*secp256k1.Commitment{publicBlind, publicValueAssetBlind}, nil)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitSum")
				return
			}

			partialPublicKeyCommit, e = secp256k1.CommitSum(context, []*secp256k1.Commitment{publicBlindExcess, publicBlindValueAssetBlind}, nil)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitSum")
				return
			}
		} else {
			partialPublicKeyCommit, e = secp256k1.CommitSum(context, []*secp256k1.Commitment{publicBlindExcess}, nil)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitSum")
				return
			}
		}

		partialPublicKey, e := secp256k1.CommitmentToPublicKey(context, partialPublicKeyCommit)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentToPublicKey")
			return
		}

		e = secp256k1.AggsigVerifyPartial(context, &partialSignature, aggregatedPublicNonce, partialPublicKey, aggregatedPublicKey, msg)
		if e != nil {
			err = errors.Wrap(e, "cannot AggsigVerifyPartial")
			return
		}

		partialSignatures = append(partialSignatures, &partialSignature)
	}

	signature, err = secp256k1.AggsigAddSignaturesSingle(context, partialSignatures, aggregatedPublicNonce)
	if err != nil {
		err = errors.Wrap(err, "cannot add sender and receiver partial signatures")
		return
	}

	err = secp256k1.AggsigVerifySingle(context, &signature, msg, nil, aggregatedPublicKey, aggregatedPublicKey, nil, false)
	if err != nil {
		err = errors.Wrap(err, "cannot verify excess signature")
		return
	}
	return
}

func getAggregatedPublicKeyAndNonce(context *secp256k1.Context, slate *Slate) (aggPublicKey *secp256k1.PublicKey, aggPublicNonce *secp256k1.PublicKey, err error) {
	var publicBlinds, publicBlindExcesses, publicNonces, publicValueAssetBlinds []*secp256k1.Commitment
	for _, party := range slate.ParticipantData {
		publicBlindExcess, e := secp256k1.CommitmentFromString(party.PublicBlindExcess)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentFromString")
			return
		}
		publicBlindExcesses = append(publicBlindExcesses, publicBlindExcess)

		publicNonce, e := secp256k1.CommitmentFromString(party.PublicNonce)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentFromString")
			return
		}
		publicNonces = append(publicNonces, publicNonce)

		if newMultipartyUtxoIsNeccessary(slate) && party.IsMultisigFundOwner {
			publicBlind, e := secp256k1.CommitmentFromString(party.PublicBlind)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitmentFromString")
				return
			}
			publicBlinds = append(publicBlinds, publicBlind)

			assetBlind, e := hex.DecodeString(party.AssetBlind)
			if e != nil {
				err = errors.Wrap(e, "cannot DecodeString")
				return
			}

			value := getMultipartyOutputValue(slate)
			valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(value, assetBlind, new([32]byte)[:])
			if e != nil {
				err = errors.Wrap(e, "cannot BlindValueGeneratorBlindSum")
				return
			}

			publicValueAssetBlind, e := secp256k1.Commit(context, valueAssetBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
			if e != nil {
				err = errors.Wrap(e, "cannot Commit")
				return
			}
			publicValueAssetBlinds = append(publicValueAssetBlinds, publicValueAssetBlind)
		}
	}

	publicKeyCommit, err := secp256k1.CommitSum(context, append(append(publicBlinds, publicValueAssetBlinds...), publicBlindExcesses...), nil)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum")
		return
	}

	aggPublicKey, err = secp256k1.CommitmentToPublicKey(context, publicKeyCommit)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitmentToPublicKey")
		return
	}

	publicNonceCommit, err := secp256k1.CommitSum(context, publicNonces, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum")
		return
	}

	aggPublicNonce, err = secp256k1.CommitmentToPublicKey(context, publicNonceCommit)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitmentToPublicKey")
		return
	}
	return
}
