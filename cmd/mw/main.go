package main

import (
	"fmt"
	"github.com/olegabu/go-mimblewimble/abci"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/libs/cli"
	"github.com/tendermint/tendermint/rpc/client"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	cmd "github.com/tendermint/tendermint/cmd/tendermint/commands"
	cfg "github.com/tendermint/tendermint/config"

	"github.com/spf13/cobra"
)

const defaultAsset = "¤"

func main() {

	var issueCmd = &cobra.Command{
		Use:   "issue amount [asset]",
		Short: "Creates outputs in the wallet",
		Long:  `Creates a coinbase output in own wallet. Use for testing only.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			amount, err := strconv.Atoi(args[0])
			if err != nil {
				return errors.Wrap(err, "cannot parse amount")
			}
			asset := defaultAsset
			if len(args) > 1 {
				asset = args[1]
			}
			txBytes, err := wallet.Issue(uint64(amount), asset)
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Issue")
			}
			fileName := "tx-issue-" + args[0] + ".json"
			err = ioutil.WriteFile(fileName, txBytes, 0644)
			if err != nil {
				return errors.Wrap(err, "cannot write file "+fileName)
			}
			fmt.Printf("wrote transaction to issue %v, send it to the network: broadcast %v\n", args[0], fileName)
			return nil
		},
	}

	var sendCmd = &cobra.Command{
		Use:   "send amount [asset]",
		Short: "Initiates a send transaction",
		Long:  `Creates a json file with a slate to pass to the receiver.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			amount, err := strconv.Atoi(args[0])
			if err != nil {
				return errors.Wrap(err, "cannot parse amount")
			}
			asset := defaultAsset
			if len(args) > 1 {
				asset = args[1]
			}
			slateBytes, err := wallet.Send(uint64(amount), asset)
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
			fmt.Printf("wrote slate, pass it to the receiver to fill in and respond: receive %v \n", fileName)
			return nil
		},
	}

	var receiveCmd = &cobra.Command{
		Use:   "receive slate_send_file",
		Short: "Receives transfer by creating a response slate",
		Long:  `Creates a json file with a response slate with own output and partial signature from sender's slate file.`,
		Args:  cobra.ExactArgs(1),
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
			fmt.Printf("wrote slate, pass it back to the sender: finalize %v\n", fileName)
			return nil
		},
	}

	var finalizeCmd = &cobra.Command{
		Use:   "finalize slate_receive_file",
		Short: "Finalizes transfer by creating a transaction from the response slate",
		Long:  `Creates a json file with a transaction to be sent to the network to get validated.`,
		Args:  cobra.ExactArgs(1),
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
			fmt.Printf("wrote transaction %v, send it to the network to get validated: broadcast %v\n", string(id), fileName)
			return nil
		},
	}

	var confirmCmd = &cobra.Command{
		Use:   "confirm transaction_id",
		Short: "Tells the wallet the transaction has been confirmed",
		Long:  `Tells the wallet the transaction has been confirmed by the network so the outputs become valid and inputs spent.`,
		Args:  cobra.ExactArgs(1),
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			transactionFileName := args[0]
			transactionBytes, err := ioutil.ReadFile(transactionFileName)
			if err != nil {
				return errors.Wrap(err, "cannot read transaction file "+transactionFileName)
			}
			tx, err := ledger.ValidateTransaction(transactionBytes)
			if err != nil {
				return errors.Wrap(err, "cannot transaction.ValidateTransaction")
			}
			fmt.Printf("transaction %v is valid\n", tx.ID)
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

	var broadcastCmd = &cobra.Command{
		Use:   "broadcast transaction_file",
		Short: "Broadcasts transaction",
		Long:  `Broadcasts transaction to the network synchronously.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			transactionFileName := args[0]
			transactionBytes, err := ioutil.ReadFile(transactionFileName)
			if err != nil {
				return errors.Wrap(err, "cannot read transaction file "+transactionFileName)
			}

			err = broadcast(transactionBytes)
			if err != nil {
				return errors.Wrap(err, "cannot broadcast")
			}

			return nil
		},
	}

	var nodeCmd = &cobra.Command{
		Use:   "node",
		Short: "Runs blockchain node",
		Long:  `Runs Tendermint node with built in Mimblewimble ABCI app.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := abci.Start()
			if err != nil {
				return errors.Wrap(err, "cannot node.Start")
			}
			return nil
		},
	}

	var rootCmd = &cobra.Command{
		Use:          "mw",
		Short:        "Wallet and validator for Mimblewimble",
		Long:         `Experimental wallet and validator for Mimblewimble protocol.`,
		SilenceUsage: true,
	}

	rootCmd.AddCommand(issueCmd, sendCmd, receiveCmd, finalizeCmd, confirmCmd, validateCmd, infoCmd, nodeCmd, broadcastCmd)

	// Tendermint commands

	tendermintRootCmd := cmd.RootCmd
	tendermintRootCmd.AddCommand(
		cmd.GenValidatorCmd,
		cmd.InitFilesCmd,
		cmd.ProbeUpnpCmd,
		cmd.LiteCmd,
		cmd.ReplayCmd,
		cmd.ReplayConsoleCmd,
		cmd.ResetAllCmd,
		cmd.ResetPrivValidatorCmd,
		cmd.ShowValidatorCmd,
		cmd.TestnetFilesCmd,
		cmd.ShowNodeIDCmd,
		cmd.GenNodeKeyCmd,
		cmd.VersionCmd)

	tendermintBaseCmd := cli.PrepareBaseCmd(tendermintRootCmd, "TM", os.ExpandEnv(filepath.Join("$HOME", cfg.DefaultTendermintDir)))

	rootCmd.AddCommand(tendermintRootCmd)

	if err := tendermintBaseCmd.Execute(); err != nil {
		panic(err)
	}
}

func broadcast(transactionBytes []byte) error {
	broadcastUrl := "tcp://0.0.0.0:26657"
	httpClient := client.NewHTTP(broadcastUrl, "/websocket")
	err := httpClient.Start()
	if err != nil {
		return errors.Wrap(err, "cannot start websocket http client")
	}
	defer func() {
		err = httpClient.Stop()
		if err != nil {
			fmt.Printf("cannot httpClient.Stop: " + err.Error())
		}
	}()

	result, err := httpClient.BroadcastTxSync(transactionBytes)
	if err != nil {
		return errors.Wrap(err, "cannot broadcast transaction")
	}

	fmt.Printf("broadcast to %v with result code=%v log=%v\n", broadcastUrl, result.Code, result.Log)

	return nil
}
