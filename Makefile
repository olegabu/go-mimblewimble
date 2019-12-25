SHELL=/bin/bash
GO111MODULE=on
GOPATH=$(realpath ../../../..)
#LIBSECPDIR=$(GOPATH)/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db
LIBSECPDIR=$(GOPATH)/src/github.com/olegabu/go-secp256k1-zkp
LIBSECP=$(LIBSECPDIR)/secp256k1-zkp/.libs/libsecp256k1.a
#echo "GOPATH: $(GOPATH)"
#echo "LIBSECDIR: $(LIBSECDIR)"
#echo "LIBSECP: $(LIBSECP)"

install: deps
	go install ./...

deps:


modules:
	go mod download

test: deps
	go test ./...



