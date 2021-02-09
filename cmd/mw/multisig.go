package main

import (
	"fmt"
	"strconv"

	"github.com/olegabu/go-mimblewimble/multisigexchange"

	"github.com/olegabu/go-mimblewimble/multisigwallet"

	"github.com/google/uuid"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var createMultiparty = &cobra.Command{
	Use:   "createMultiparty amount asset transactionID needBroadcast myIP:myPort otherIP1:otherPort1 otherIP2:otherPort2 ...",
	Short: "Creates multiparty UTXO",
	Long:  `Creates multiparty UTXO`,
	Args:  cobra.MinimumNArgs(6),
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

		address := args[4]

		participantsAddresses := make([]string, 0)
		for i := 5; i < len(args); i++ {
			participantsAddresses = append(participantsAddresses, args[i])
		}

		w, err := multisigwallet.NewWallet(flagPersist)
		if err != nil {
			return errors.Wrap(err, "cannot create wallet")
		}
		defer w.Close()

		commit, err := multisigexchange.CreateMultipartyUTXO(w, address, uint64(amount), asset, transactionID, participantsAddresses, flagAddress, needBroadcast)
		if err != nil {
			return errors.Wrap(err, "cannot CreateMultisigUTXO")
		}

		fmt.Println("created multiparty output with commit:", commit)
		return nil
	},
}

var spendMultiparty = &cobra.Command{
	Use:   "spendMultiparty multipartyOutputCommit amount asset transactionID needBroadcast myIP:myPort receiverIP:receiverPort otherIP1:otherPort1 otherIP2:otherPort2 ...",
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

		address := args[5]
		receiverAddress := args[6]

		participantsAddresses := make([]string, 0)
		for i := 7; i < len(args); i++ {
			participantsAddresses = append(participantsAddresses, args[i])
		}

		w, err := multisigwallet.NewWallet(flagPersist)
		if err != nil {
			return errors.Wrap(err, "cannot create wallet")
		}
		defer w.Close()

		commit, err := multisigexchange.SpendMultipartyUTXO(w, multipartyOutputCommit, address, uint64(amount), asset, transactionID, participantsAddresses,
			receiverAddress, flagAddress, needBroadcast)
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

var receiveMultiparty = &cobra.Command{
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

		w, err := multisigwallet.NewWallet(flagPersist)
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
