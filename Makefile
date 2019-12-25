SHELL=/bin/bash
GO111MODULE=on
LIBSECPKGPDIR=$(GOPATH)/pkg/mod/github.com/olegabu/go-secp256k1-zkp@v0.0.0-20191113113909-cc0ed62ae4db
LIBSECPSRCDIR=$(GOPATH)/src/github.com/olegabu/go-secp256k1-zkp
LIBSECP=$(LIBSECPDIR)/secp256k1-zkp/.libs/libsecp256k1.a

install: deps
	go install ./...

deps: $(LIBSECP)

$(LIBSECP): modules
	pushd $(LIBSECPKGPDIR) &&\
	chmod +x secp256k1-zkp/autogen.sh  &&\
	find . -type d -exec chmod 777 {} \;  &&\
	CFLAGS="-fPIC -DPIC" make &&\
	popd

modules: info
	go mod download

info:
	echo "GOPATH: $(GOPATH)" &&\
	echo "LIBSECPKGPDIR: $(LIBSECPKGPDIR)" &&\
	echo "LIBSECPSRCDIR: $(LIBSECPSRCDIR)" &&\
	echo "LIBSECP: $(LIBSECP)"

test: deps
	go test ./...



