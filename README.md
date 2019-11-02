#  Library for forming and validating transactions in mimblewimble protocol

## Building and testing

Note Go modules are not yet supported.

```bash
unset GO111MODULE
go install
go test
```

If you get a build error from linker like

```
/usr/lib/go-1.13/pkg/tool/linux_amd64/link: running gcc failed: exit status 1
gcc: error: /home/oleg/go/src/github.com/olegabu/go-secp256k1-zkp/secp256k1-zkp/.libs/libsecp256k1.a: No such file or directory
```

please build [go-secp256k1-zkp](https://github.com/olegabu/go-secp256k1-zkp) library

```bash
# clone if needed
mkdir -p $GOPATH/github.com/olegabu
cd $GOPATH/github.com/olegabu
git clone https://github.com/olegabu/go-secp256k1-zkp

# build
cd $GOPATH/github.com/olegabu/go-secp256k1-zkp
make
```

this will build dependant C libraries secp256k1-zkp into `$GOPATH/github.com/olegabu/go-secp256k1-zkp/secp256k1-zkp/.libs`.
