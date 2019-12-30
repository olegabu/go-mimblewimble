SHELL=/bin/bash
GO111MODULE=on
#LIBSECPKGPDIR=$(GOPATH)/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db
LIBSECPSRCDIR=../go-secp256k1-zkp
LIBSECP=$(LIBSECPSRCDIR)/secp256k1-zkp/.libs/libsecp256k1.a

install: deps
	go install ./...

deps: $(LIBSECP)

$(LIBSECP): modules
	pushd $(LIBSECPSRCDIR) &&\
	make && \
	popd

modules: info
	go mod download

info:
	echo "GOPATH: $(GOPATH)" &&\
#	echo "LIBSECPKGPDIR: $(LIBSECPKGPDIR)" &&\
	echo "LIBSECPSRCDIR: $(LIBSECPSRCDIR)" &&\
	echo "LIBSECP: $(LIBSECP)"

test:
	pushd ./ledger && go test -v && popd
	pushd ./wallet && go test -v && popd




