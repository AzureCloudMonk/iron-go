GO := go
GOFMT := gofmt

ROOT := $(realpath $(PWD))
VENDOR := $(ROOT)/vendor
GOPATH := "$(VENDOR):$(GOPATH)"

PREFIX := github.com/kitcambridge/iron-go
DEPS := golang.org/x/crypto/pbkdf2

fetch:
	mkdir -p $(VENDOR)
	GOPATH=$(GOPATH) $(GO) get -d -u $(DEPS)

fmt:
	$(GOFMT) -w $(ROOT)

test:
	GOPATH=$(GOPATH) $(GO) test $(addprefix $(PREFIX)/,$(PACKAGES))

clean:
	rm -rf $(VENDOR)

.PHONY: fetch fmt test clean
