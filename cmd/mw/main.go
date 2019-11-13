package main

import (
	"fmt"
	"github.com/olegabu/go-mimblewimble/node"
	"github.com/olegabu/go-mimblewimble/transaction"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/pkg/errors"
	"io/ioutil"
	"strconv"

	"github.com/spf13/cobra"
)

func main() {

	defer wallet.Db.Close()

	var issueCmd = &cobra.Command{
		Use:   "issue amount",
		Short: "Creates outputs in the wallet",
		Long:  `Creates a coinbase output in own wallet. Use for testing only.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			amount, err := strconv.Atoi(args[0])
			if err != nil {
				return errors.Wrap(err, "cannot parse amount")
			}
			err = wallet.Issue(uint64(amount))
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Issue")
			}
			return nil
		},
	}

	var sendCmd = &cobra.Command{
		Use:   "send amount",
		Short: "Initiates a send transaction",
		Long:  `Creates a json file with a slate to pass to the receiver.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			amount, err := strconv.Atoi(args[0])
			if err != nil {
				return errors.Wrap(err, "cannot parse amount")
			}
			slateBytes, err := wallet.Send(uint64(amount))
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Send")
			}
			id, err := wallet.ParseIDFromSlate(slateBytes)
			if err != nil {
				return errors.Wrap(err, "cannot parse id from slate")
			}
			fileName := "slate-send-" + string(id) + ".json"
			err = ioutil.WriteFile(fileName, slateBytes, 0644)
			if err != nil {
				return errors.Wrap(err, "cannot write file "+fileName)
			}
			fmt.Printf("wrote slate to %v pass it to the receiver to fill in and respond\n", fileName)
			return nil
		},
	}

	var receiveCmd = &cobra.Command{
		Use:   "receive slate_send_file",
		Short: "Receives transfer by creating a response slate",
		Long:  `Creates a json file with a response slate with own output and partial signature from sender's slate file.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slateFileName := args[0]
			slateBytes, err := ioutil.ReadFile(slateFileName)
			if err != nil {
				return errors.Wrap(err, "cannot read sender slate file "+slateFileName)
			}
			responseSlateBytes, err := wallet.Receive(slateBytes)
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Receive")
			}
			id, err := wallet.ParseIDFromSlate(responseSlateBytes)
			if err != nil {
				return errors.Wrap(err, "cannot parse id from slate")
			}
			fileName := "slate-receive-" + string(id) + ".json"
			err = ioutil.WriteFile(fileName, responseSlateBytes, 0644)
			if err != nil {
				return errors.Wrap(err, "cannot write file "+fileName)
			}
			fmt.Printf("wrote slate to %v pass it back to the sender to finalize\n", fileName)
			return nil
		},
	}

	var finalizeCmd = &cobra.Command{
		Use:   "finalize slate_receive_file",
		Short: "Finalizes transfer by creating a transaction from the response slate",
		Long:  `Creates a json file with a transaction to be sent to the network to get validated.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slateFileName := args[0]
			slateBytes, err := ioutil.ReadFile(slateFileName)
			if err != nil {
				return errors.Wrap(err, "cannot read receiver slate file "+slateFileName)
			}
			txBytes, err := wallet.Finalize(slateBytes)
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Finalize")
			}
			id, err := wallet.ParseIDFromSlate(slateBytes)
			if err != nil {
				return errors.Wrap(err, "cannot parse id from slate")
			}
			fileName := "tx-" + string(id) + ".json"
			err = ioutil.WriteFile(fileName, txBytes, 0644)
			if err != nil {
				return errors.Wrap(err, "cannot write file "+fileName)
			}
			fmt.Printf("wrote transaction %v to %v send it to the network to get validated\n", string(id), fileName)
			return nil
		},
	}

	var confirmCmd = &cobra.Command{
		Use:   "confirm transaction_id",
		Short: "Tells the wallet the transaction has been confirmed",
		Long:  `Tells the wallet the transaction has been confirmed by the network so the outputs become valid and inputs spent.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := wallet.Confirm([]byte(args[0]))
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Confirm")
			}
			return nil
		},
	}

	var validateCmd = &cobra.Command{
		Use:   "validate transaction_file",
		Short: "Validates transaction",
		Long:  `Validates transaction's signature, sum of inputs and outputs and bulletproofs.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			transactionFileName := args[0]
			transactionBytes, err := ioutil.ReadFile(transactionFileName)
			if err != nil {
				return errors.Wrap(err, "cannot read transaction file "+transactionFileName)
			}
			_, err = transaction.Validate(transactionBytes)
			if err != nil {
				return errors.Wrap(err, "cannot transaction.Validate")
			}
			fmt.Printf("transaction is valid\n")
			return nil
		},
	}

	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Prints out outputs, slates, transactions",
		Long:  `Prints out outputs, slates, transactions stored in the wallet.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := wallet.Info()
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Info")
			}
			return nil
		},
	}

	var nodeCmd = &cobra.Command{
		Use:   "node",
		Short: "Runs blockchain node",
		Long:  `Runs Tendermint node with built in Mimblewimble ABCI app.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := node.Start()
			if err != nil {
				return errors.Wrap(err, "cannot node.Start")
			}
			return nil
		},
	}

	/*

		func cmdKVStore(cmd *cobra.Command, args []string) error {
			logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))

			// Create the application - in memory or persisted to disk
			var app types.Application
			if flagPersist == "" {
				app = kvstore.NewKVStoreApplication()
			} else {
				app = kvstore.NewPersistentKVStoreApplication(flagPersist)
				app.(*kvstore.PersistentKVStoreApplication).SetLogger(logger.With("module", "kvstore"))
			}

			// Start the listener
			srv, err := server.NewServer(flagAddress, flagAbci, app)
			if err != nil {
				return err
			}
			srv.SetLogger(logger.With("module", "abci-server"))
			if err := srv.Start(); err != nil {
				return err
			}

			// Stop upon receiving SIGTERM or CTRL-C.
			cmn.TrapSignal(logger, func() {
				// Cleanup
				srv.Stop()
			})

			// Run forever.
			select {}
		}

	*/

	var rootCmd = &cobra.Command{
		Use:          "mw",
		Short:        "Wallet and validator for Mimblewimble",
		Long:         `Experimental wallet and validator for Mimblewimble protocol.`,
		SilenceUsage: true,
	}

	rootCmd.AddCommand(issueCmd, sendCmd, receiveCmd, finalizeCmd, confirmCmd, validateCmd, infoCmd, nodeCmd)

	_ = rootCmd.Execute()
}
