package main

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/olegabu/go-mimblewimble/abci"
	"github.com/olegabu/go-mimblewimble/ledger"
	"github.com/olegabu/go-mimblewimble/wallet"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	tendermintCmd "github.com/tendermint/tendermint/cmd/tendermint/commands"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/cli"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
)

const defaultAsset = "¤"

// flags
var (
	// global
	flagAddress string
	flagPersist string
)

var rootCmd *cobra.Command

// to bind MW_ env variables to flags of all commands
// ex.: db directory can be set with --persist flag:
// mw info --persist $HOME/.mw_x
// or MW_PERSIST env var:
// MW_PERSIST=$HOME/.mw_x mw info
// see https://github.com/spf13/viper/issues/397#issuecomment-544272457
func init() {
	cobra.OnInitialize(func() {
		// bind env variables
		// see https://github.com/spf13/viper#working-with-environment-variables
		viper.SetEnvPrefix("MW")
		viper.AutomaticEnv()
		postInitCommands(rootCmd.Commands())
	})
}

func postInitCommands(commands []*cobra.Command) {
	for _, c := range commands {
		presetRequiredFlags(c)
		if c.HasSubCommands() {
			postInitCommands(c.Commands())
		}
	}
}

func presetRequiredFlags(cmd *cobra.Command) {
	viper.BindPFlags(cmd.Flags())
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if viper.IsSet(f.Name) && viper.GetString(f.Name) != "" {
			cmd.Flags().Set(f.Name, viper.GetString(f.Name))
		}
	})
}

func main() {

	var initCmd = &cobra.Command{
		Use:     "init [mnemonic]",
		Short:   "Creates or recovers user's secret key",
		Long:    `Creates user's master secret key if not found, or re-creates it from a supplied mnemonic'.`,
		Example: `to create: mw init, to recover: mw init "citizen convince comfort sleep student potato frequent bike catalog dinosaur speed knife"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := wallet.NewWalletWithoutMasterKey(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot create wallet")
			}
			defer w.Close()

			var mnemonic string
			if len(args) > 0 {
				mnemonic = args[0]
			}

			fmt.Printf("master secret key is in %v\n", flagPersist)

			createdMnemonic, err := w.InitMasterKey(mnemonic)
			if err != nil {
				return errors.Wrap(err, "cannot initialize key")
			}

			if len(createdMnemonic) > 0 {
				fmt.Printf("please record all the words of this mnemonic, use it if you ever need to recover your key\n%s\n", createdMnemonic)
			}

			return nil
		},
	}

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

			w, err := wallet.NewWallet(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot create wallet")
			}
			defer w.Close()

			txBytes, err := w.Issue(uint64(amount), asset)
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Issue")
			}
			fileName := "issue-" + args[0] + ".json"
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

			w, err := wallet.NewWallet(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot create wallet")
			}
			defer w.Close()

			slateBytes, err := w.Send(uint64(amount), asset)
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

			w, err := wallet.NewWallet(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot create wallet")
			}
			defer w.Close()

			responseSlateBytes, err := w.Receive(slateBytes)
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

			w, err := wallet.NewWallet(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot create wallet")
			}
			defer w.Close()

			txBytes, err := w.Finalize(slateBytes)
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
			fmt.Printf("wrote transaction %v, send it to the network to get validated: broadcast %v\nthen tell the wallet the transaction has been confirmed: confirm %v\n", string(id), fileName, string(id))
			return nil
		},
	}

	var confirmCmd = &cobra.Command{
		Use:   "confirm transaction_id",
		Short: "Tells the wallet the transaction has been confirmed",
		Long:  `Tells the wallet the transaction has been confirmed by the network so the outputs become valid and inputs spent.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := wallet.NewWallet(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot create wallet")
			}
			defer w.Close()

			err = w.Confirm([]byte(args[0]))
			if err != nil {
				return errors.Wrap(err, "cannot wallet.Confirm")
			}
			fmt.Printf("confirmed transaction: marked inputs as spent and outputs as confirmed")
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
			tx, err := ledger.ValidateTransactionBytes(transactionBytes)
			if err != nil {
				return errors.Wrap(err, "cannot transaction.ValidateTransactionBytes")
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

			w, err := wallet.NewWallet(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot create wallet")
			}
			defer w.Close()

			err = w.Info()
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

			client, err := abci.NewClient(flagAddress)
			if err != nil {
				return errors.Wrap(err, "cannot get new client")
			}
			defer client.Stop()

			err = client.Broadcast(transactionBytes)
			if err != nil {
				return errors.Wrap(err, "cannot client.Broadcast")
			}

			return nil
		},
	}
	broadcastCmd.Flags().StringVarP(&flagAddress,
		"address",
		"",
		"tcp://0.0.0.0:26657",
		"address of tendermint socket to broadcast to")

	var eventsCmd = &cobra.Command{
		Use:   "events",
		Short: "Listens to and prints transaction events",
		Long:  `Subscribes to events from the network and prints out transaction events.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := abci.NewClient(flagAddress)
			if err != nil {
				return errors.Wrap(err, "cannot get new client")
			}
			defer client.Stop()

			err = client.ListenForTxEvents(client.PrintTxEvent)
			if err != nil {
				return errors.Wrap(err, "cannot client.ListenForEvents")
			}

			return nil
		},
	}
	eventsCmd.Flags().StringVarP(&flagAddress,
		"address",
		"",
		"tcp://0.0.0.0:26657",
		"address of tendermint socket to subscribe for events")

	var listenCmd = &cobra.Command{
		Use:   "listen",
		Short: "Listens to and processes successful transaction events",
		Long:  `Subscribes to events from the network and updates wallet with confirmed transactions.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := abci.NewClient(flagAddress)
			if err != nil {
				return errors.Wrap(err, "cannot get new client")
			}
			defer client.Stop()

			err = client.ListenForSuccessfulTxEvents(func(transactionId []byte) {

				w, err := wallet.NewWallet(flagPersist)
				if err != nil {
					fmt.Println(errors.Wrap(err, "cannot create wallet"))
				}
				defer w.Close()

				err = w.Confirm(transactionId)
				if err != nil {
					fmt.Println(errors.Wrapf(err, "cannot wallet.Confirm transaction %v", string(transactionId)).Error())
				} else {
					err = w.Info()
					if err != nil {
						fmt.Println(errors.Wrap(err, "cannot wallet.Info").Error())
					}
				}
			})
			if err != nil {
				return errors.Wrap(err, "cannot abci.ListenForEvents")
			}

			return nil
		},
	}
	listenCmd.Flags().StringVarP(&flagAddress,
		"address",
		"",
		"tcp://0.0.0.0:26657",
		"address of tendermint socket to subscribe for events")

	var nodeCmd = &cobra.Command{
		Use:   "node",
		Short: "Runs blockchain node",
		Long:  `Runs Tendermint node with built in Mimblewimble ABCI app.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := abci.Start(flagPersist)
			if err != nil {
				return errors.Wrap(err, "cannot abci.Start")
			}
			return nil
		},
	}

	rootCmd = &cobra.Command{
		Use:          "mw",
		Short:        "Wallet and validator for Mimblewimble",
		Long:         `Experimental wallet and validator for Mimblewimble protocol.`,
		SilenceUsage: true,
	}

	rootCmd.AddCommand(initCmd, issueCmd, sendCmd, receiveCmd, finalizeCmd, confirmCmd, validateCmd, infoCmd, nodeCmd, broadcastCmd, eventsCmd, listenCmd)

	dir, err := homedir.Dir()
	if err != nil {
		panic("cannot get homedir")
	}
	mwroot := filepath.Join(dir, ".mw")

	rootCmd.PersistentFlags().StringVarP(&flagPersist, "persist", "", mwroot, "directory to use to store databases and user's master secret key")

	// Tendermint commands

	tendermintRootCmd := tendermintCmd.RootCmd
	tendermintRootCmd.AddCommand(
		tendermintCmd.GenValidatorCmd,
		tendermintCmd.InitFilesCmd,
		tendermintCmd.ProbeUpnpCmd,
		tendermintCmd.LiteCmd,
		tendermintCmd.ReplayCmd,
		tendermintCmd.ReplayConsoleCmd,
		tendermintCmd.ResetAllCmd,
		tendermintCmd.ResetPrivValidatorCmd,
		tendermintCmd.ShowValidatorCmd,
		tendermintCmd.TestnetFilesCmd,
		tendermintCmd.ShowNodeIDCmd,
		tendermintCmd.GenNodeKeyCmd,
		tendermintCmd.VersionCmd)

	tendermintBaseCmd := cli.PrepareBaseCmd(tendermintRootCmd, "TM", os.ExpandEnv(filepath.Join("$HOME", cfg.DefaultTendermintDir)))

	rootCmd.AddCommand(tendermintRootCmd)

	if err := tendermintBaseCmd.Execute(); err != nil {
		panic(err)
	}
}
