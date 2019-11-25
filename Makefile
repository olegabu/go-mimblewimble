SHELL := /bin/bash
LIBSECP := $(GOPATH)/pkg/mod/github.com/olegabu/go-secp256k1-zkp/secp256k1-zkp/.libs/libsecp256k1.a

install: deps
	go install ./...

deps: $(LIBSECP)

$(LIBSECP): modules
	pushd ${GOPATH}/pkg/mod/github.com/olegabu/go-secp256k1-zkp* &&\
	chmod +x secp256k1-zkp/autogen.sh  &&\
	find . -type d -exec chmod 777 {} \;  &&\
	CFLAGS="-fPIC" make  &&\
	popd

modules:
	go mod download

test: deps
	go test ./...
