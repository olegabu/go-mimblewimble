#  Experimental wallet and library for Mimblewimble protocol

## Building

```bash
go install ./cmd/mw
```

If you see an error showing the dependent C library was not found:
```
gcc: error: ../../go/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db/secp256k1-zkp/.libs/libsecp256k1.a: No such file or directory
```
You'll have to build it yourself in the directory where `go mod` put `go-secp256k1-zkp` package.
```bash
cd $GOPATH/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db/secp256k1-zkp
```
Fix file and dir permissions there.
```bash
chmod +x secp256k1-zkp/autogen.sh
find . -type d -exec chmod 777 {} \;
make
``` 

You also may need to tell which repo is private.
```bash
export GOPRIVATE=github.com/olegabu/go-secp256k1-zkp
```
