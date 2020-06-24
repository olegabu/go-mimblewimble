module github.com/olegabu/go-mimblewimble

go 1.13

replace github.com/olegabu/go-secp256k1-zkp => ../go-secp256k1-zkp

require (
	github.com/blockcypher/libgrin v2.0.0+incompatible
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/google/uuid v1.1.1
	github.com/hyperledger/fabric v1.4.4
	github.com/magiconair/properties v1.8.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olegabu/go-secp256k1-zkp v0.1.0
	github.com/olekukonko/tablewriter v0.0.2
	github.com/pkg/errors v0.8.1
	github.com/sethgrid/pester v0.0.0-20190127155807-68a33a018ad0 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.5.0
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/goleveldb v1.0.1-0.20190318030020-c3a204f8e965
	github.com/tendermint/tendermint v0.32.7
	golang.org/x/crypto v0.0.0-20200311171314-f7b00557c8c4
)
