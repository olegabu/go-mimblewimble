module github.com/olegabu/go-mimblewimble

go 1.14

//replace github.com/olegabu/go-secp256k1-zkp => ../go-secp256k1-zkp

require (
	github.com/blockcypher/libgrin v2.0.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/hyperledger/fabric v1.4.6
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olegabu/go-secp256k1-zkp v0.2.2
	github.com/olekukonko/tablewriter v0.0.2
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.5.0
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/goleveldb v1.0.1-0.20190318030020-c3a204f8e965
	github.com/tendermint/tendermint v0.32.7
	golang.org/x/crypto v0.0.0-20200214034016-1d94cc7ab1c6
)
