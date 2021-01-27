package multisigwallet

import (
	"encoding/hex"

	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

func (t *Wallet) createPartialSignature(slate *Slate, savedSlate *SavedSlate) (partialSignatureString string, err error) {
	publicBlinds, publicBlindExcesses, publicNonces, publicValueAssetBlinds, err := t.getSharedData(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot extractParticipantData")
		return
	}

	aggregatedPublicKey, err := t.calculateAggregatedPublicKey(publicBlinds, publicValueAssetBlinds, publicBlindExcesses)
	if err != nil {
		err = errors.Wrap(err, "cannot computeAggregatedPublicKey")
		return
	}

	aggregatedPublicNonce, err := t.calculateAggregatedNonce(publicNonces)
	if err != nil {
		err = errors.Wrap(err, "cannot computeAggregatedNonce")
		return
	}

	msg := ledger.KernelSignatureMessage(savedSlate.Transaction.Body.Kernels[0])

	var privateKey [32]byte
	newMultipartyUtxoIsNeccessary := slate.Amount > 0
	if newMultipartyUtxoIsNeccessary {
		assetBlind, e := t.secret(savedSlate.AssetBlindIndex)
		if e != nil {
			err = errors.Wrap(e, "cannot DecodeString")
			return
		}

		blind, e := t.secret(savedSlate.BlindIndex)
		if e != nil {
			err = errors.Wrap(e, "cannot get blind")
			return
		}

		blindValueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(uint64(slate.Amount), assetBlind[:], blind[:])
		if e != nil {
			err = errors.Wrap(e, "cannot BlindValueGeneratorBlindSum")
			return
		}

		privateKey, e = secp256k1.BlindSum(t.context, [][]byte{blindValueAssetBlind[:], savedSlate.ExcessBlind[:]}, nil)
		if e != nil {
			err = errors.Wrap(e, "cannot compute private key")
			return
		}
	} else {
		privateKey, err = secp256k1.BlindSum(t.context, [][]byte{savedSlate.ExcessBlind[:]}, nil)
		if err != nil {
			err = errors.Wrap(err, "cannot compute private key")
			return
		}
	}

	partialSignature, err := secp256k1.AggsigSignPartial(t.context, privateKey[:], savedSlate.Nonce[:], aggregatedPublicNonce, aggregatedPublicKey, msg)
	if err != nil {
		err = errors.Wrap(err, "cannot calculate receiver's partial signature")
		return
	}
	partialSignatureBytes := secp256k1.AggsigSignaturePartialSerialize(&partialSignature)
	partialSignatureString = hex.EncodeToString(partialSignatureBytes[:])
	return
}

func (t *Wallet) getSharedData(
	slate *Slate,
) (
	publicBlinds []*secp256k1.Commitment,
	publicBlindExcesses []*secp256k1.Commitment,
	publicNonces []*secp256k1.Commitment,
	publicValueAssetBlinds []*secp256k1.Commitment,
	err error,
) {
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

		newMultipartyUtxoIsNeccessary := slate.Amount > 0
		if newMultipartyUtxoIsNeccessary {
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

			valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(uint64(slate.Amount), assetBlind, new([32]byte)[:])
			if e != nil {
				err = errors.Wrap(e, "cannot BlindValueGeneratorBlindSum")
				return
			}

			publicValueAssetBlind, e := secp256k1.Commit(t.context, valueAssetBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
			if e != nil {
				err = errors.Wrap(e, "cannot Commit")
				return
			}
			publicValueAssetBlinds = append(publicValueAssetBlinds, publicValueAssetBlind)
		}
	}
	return
}

func (t *Wallet) calculateAggregatedPublicKey(
	publicBlinds []*secp256k1.Commitment,
	publicValueAssetBlinds []*secp256k1.Commitment,
	publicBlindExcesses []*secp256k1.Commitment,
) (
	publicKey *secp256k1.PublicKey,
	err error,
) {
	commit, err := secp256k1.CommitSum(t.context, append(append(publicBlinds, publicValueAssetBlinds...), publicBlindExcesses...), nil)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum")
		return
	}

	publicKey, err = secp256k1.CommitmentToPublicKey(t.context, commit)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitmentToPublicKey")
		return
	}
	return
}

func (t *Wallet) calculateAggregatedNonce(publicNonces []*secp256k1.Commitment) (publicNonce *secp256k1.PublicKey, err error) {
	commit, err := secp256k1.CommitSum(t.context, publicNonces, nil)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitSum")
		return
	}

	publicNonce, err = secp256k1.CommitmentToPublicKey(t.context, commit)
	if err != nil {
		err = errors.Wrap(err, "cannot CommitmentToPublicKey")
		return
	}
	return
}

func (t *Wallet) aggregatePartialSignatures(slate *Slate) (signature secp256k1.AggsigSignature, err error) {
	publicBlinds, publicBlindExcesses, publicNonces, publicValueAssetBlinds, err := t.getSharedData(slate)
	if err != nil {
		err = errors.Wrap(err, "cannot extractParticipantData")
		return
	}

	msg := ledger.KernelSignatureMessage(slate.Transaction.Body.Kernels[0])

	aggregatedPublicKey, err := t.calculateAggregatedPublicKey(publicBlinds, publicValueAssetBlinds, publicBlindExcesses)
	if err != nil {
		err = errors.Wrap(err, "cannot computeAggregatedPublicKey")
		return
	}

	aggregatedPublicNonce, err := t.calculateAggregatedNonce(publicNonces)
	if err != nil {
		err = errors.Wrap(err, "cannot computeAggregatedNonce")
		return
	}

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
		newMultipartyUtxoIsNeccessary := slate.Amount > 0
		if newMultipartyUtxoIsNeccessary {
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

			valueAssetBlind, e := secp256k1.BlindValueGeneratorBlindSum(uint64(slate.Amount), assetBlind, new([32]byte)[:])
			if e != nil {
				err = errors.Wrap(e, "cannot BlindValueGeneratorBlindSum")
				return
			}

			publicValueAssetBlind, e := secp256k1.Commit(t.context, valueAssetBlind[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
			if e != nil {
				err = errors.Wrap(e, "cannot Commit")
				return
			}

			publicBlindValueAssetBlind, e := secp256k1.CommitSum(t.context, []*secp256k1.Commitment{publicBlind, publicValueAssetBlind}, nil)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitSum")
				return
			}

			partialPublicKeyCommit, e = secp256k1.CommitSum(t.context, []*secp256k1.Commitment{publicBlindExcess, publicBlindValueAssetBlind}, nil)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitSum")
				return
			}
		} else {
			partialPublicKeyCommit, e = secp256k1.CommitSum(t.context, []*secp256k1.Commitment{publicBlindExcess}, nil)
			if e != nil {
				err = errors.Wrap(e, "cannot CommitSum")
				return
			}
		}

		partialPublicKey, e := secp256k1.CommitmentToPublicKey(t.context, partialPublicKeyCommit)
		if e != nil {
			err = errors.Wrap(e, "cannot CommitmentToPublicKey")
			return
		}

		e = secp256k1.AggsigVerifyPartial(t.context, &partialSignature, aggregatedPublicNonce, partialPublicKey, aggregatedPublicKey, msg)
		if e != nil {
			err = errors.Wrap(e, "cannot AggsigVerifyPartial")
			return
		}

		partialSignatures = append(partialSignatures, &partialSignature)
	}

	signature, err = secp256k1.AggsigAddSignaturesSingle(t.context, partialSignatures, aggregatedPublicNonce)
	if err != nil {
		err = errors.Wrap(err, "cannot add sender and receiver partial signatures")
		return
	}

	err = secp256k1.AggsigVerifySingle(t.context, &signature, msg, nil, aggregatedPublicKey, aggregatedPublicKey, nil, false)
	if err != nil {
		err = errors.Wrap(err, "cannot verify excess signature")
		return
	}
	return
}
