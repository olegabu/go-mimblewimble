package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/olegabu/go-mimblewimble/multisigexchange"

	"github.com/olegabu/go-mimblewimble/wallet"

	"github.com/google/uuid"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var createMultipartyCmd = &cobra.Command{
	Use:   "createMultiparty amount asset transactionID needBroadcast threshold myName@myIP:myPort otherName1@otherIP1:otherPort1 otherName2@otherIP2:otherPort2 ...",
	Short: "Creates multiparty UTXO",
	Long:  `Creates multiparty UTXO`,
	Args:  cobra.MinimumNArgs(7),
	RunE: func(cmd *cobra.Command, args []string) error {
		amount, err := strconv.Atoi(args[0])
		if err != nil {
			return errors.Wrap(err, "cannot parse amount")
		}

		asset := args[1]

		var transactionID uuid.UUID
		err = transactionID.UnmarshalText([]byte(args[2]))
		if err != nil {
			return errors.Wrap(err, "cannot parse transactionID")
		}

		needBroadcast, err := strconv.ParseBool(args[3])
		if err != nil {
			return errors.Wrap(err, "cannot parse needBroadcast")
		}

		threshold, err := strconv.Atoi(args[4])
		if err != nil {
			return errors.Wrap(err, "cannot parse threshold")
		}

		parts := strings.Split(args[5], "@")
		name := parts[0]
		address := parts[1]

		participantsAddresses := make([]string, 0)
		for i := 6; i < len(args); i++ {
			parts := strings.Split(args[i], "@")
			participantsAddresses = append(participantsAddresses, parts[1])
		}

		w, err := wallet.NewWallet(flagPersist)
		if err != nil {
			return errors.Wrap(err, "cannot create wallet")
		}
		defer w.Close()

		commit, err := multisigexchange.CreateMultipartyUTXO(w, name, address, uint64(amount), asset, transactionID, participantsAddresses, flagAddress, needBroadcast, threshold)
		if err != nil {
			return errors.Wrap(err, "cannot CreateMultisigUTXO")
		}

		fmt.Println("created multiparty output with commit:", commit)
		return nil
	},
}

var spendMultipartyCmd = &cobra.Command{
	Use:   "spendMultiparty multipartyOutputCommit amount asset transactionID needBroadcast myName@myIP:myPort receiverIP:receiverPort otherName1@otherIP1:otherPort1 otherName2@otherIP2:otherPort2 ...",
	Short: "Spends multiparty UTXO",
	Long:  `Spends multiparty UTXO`,
	Args:  cobra.MinimumNArgs(8),
	RunE: func(cmd *cobra.Command, args []string) error {
		multipartyOutputCommit := args[0]
		amount, err := strconv.Atoi(args[1])
		if err != nil {
			return errors.Wrap(err, "cannot parse amount")
		}

		asset := args[2]

		var transactionID uuid.UUID
		err = transactionID.UnmarshalText([]byte(args[3]))
		if err != nil {
			return errors.Wrap(err, "cannot parse transactionID")
		}

		needBroadcast, err := strconv.ParseBool(args[4])
		if err != nil {
			return errors.Wrap(err, "cannot parse needBroadcast")
		}

		parts := strings.Split(args[5], "@")
		name := parts[0]
		address := parts[1]
		receiverAddress := args[6]

		participantsAddresses := make([]string, 0)
		missingParticipantsNames := make([]string, 0)
		for i := 7; i < len(args); i++ {
			parts := strings.Split(args[i], "@")
			if len(parts) == 2 {
				participantsAddresses = append(participantsAddresses, parts[1])
			} else {
				missingParticipantsNames = append(missingParticipantsNames, parts[0])
			}
		}

		w, err := wallet.NewWallet(flagPersist)
		if err != nil {
			return errors.Wrap(err, "cannot create wallet")
		}
		defer w.Close()

		commit, err := multisigexchange.SpendMultipartyUTXO(w, multipartyOutputCommit, name, address, uint64(amount), asset, transactionID, participantsAddresses,
			missingParticipantsNames, receiverAddress, flagAddress, needBroadcast)
		if err != nil {
			return errors.Wrap(err, "cannot SpendMultipartyUTXO")
		}

		fmt.Println("spended multiparty output with commit:", multipartyOutputCommit)
		if commit != "" {
			fmt.Println("created multiparty output with commit:", commit)
		}
		return nil
	},
}

var receiveMultipartyCmd = &cobra.Command{
	Use:   "receiveMultiparty amount asset transactionID myIP:myPort",
	Short: "Receives multiparty UTXO",
	Long:  `Receives multiparty UTXO`,
	Args:  cobra.MinimumNArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		amount, err := strconv.Atoi(args[0])
		if err != nil {
			return errors.Wrap(err, "cannot parse amount")
		}

		asset := args[1]

		var transactionID uuid.UUID
		err = transactionID.UnmarshalText([]byte(args[2]))
		if err != nil {
			return errors.Wrap(err, "cannot parse transactionID")
		}

		address := args[3]

		w, err := wallet.NewWallet(flagPersist)
		if err != nil {
			return errors.Wrap(err, "cannot create wallet")
		}
		defer w.Close()

		commit, err := multisigexchange.ReceiveFromMultipartyUTXO(w, address, uint64(amount), asset, transactionID, flagAddress)
		if err != nil {
			return errors.Wrap(err, "cannot ReceiveFromMultipartyUTXO")
		}

		fmt.Println("received new output with commit:", commit)
		return nil
	},
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Syncs the wallet with the state of the ledger",
	Long:  `Syncs the wallet with the state of the ledger`,
	Args:  cobra.MinimumNArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := wallet.NewWallet(flagPersist)
		if err != nil {
			return errors.Wrap(err, "cannot create wallet")
		}
		defer w.Close()

		err = w.Sync(flagAddress)
		if err != nil {
			return errors.Wrap(err, "cannot sync wallet with the state of the ledger")
		}
		return nil
	},
}
