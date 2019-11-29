SHELL=/bin/bash
#LIBSECPDIR=$(GOPATH)/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db
LIBSECPDIR=$(GOPATH)/src/github.com/olegabu/go-secp256k1-zkp
LIBSECP=$(LIBSECPDIR)/secp256k1-zkp/.libs/libsecp256k1.a
GO111MODULE=on

install: deps
	go install ./...

deps: $(LIBSECP)

$(LIBSECP): modules
	pushd $(LIBSECPDIR) &&\
	chmod +x secp256k1-zkp/autogen.sh  &&\
	find . -type d -exec chmod 777 {} \;  &&\
	CFLAGS="-fPIC -DPIC" make &&\
	popd

modules:
	go mod download

test: deps
	go test ./...



