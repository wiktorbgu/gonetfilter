GO ?= go

.PHONY: test build build-unified build-separate clean

test:
	$(GO) test ./...
	cd third_party/nftables && $(GO) test ./expr

build:
	./scripts/build.sh all all

build-unified:
	./scripts/build.sh unified all

build-separate:
	./scripts/build.sh separate all

clean:
	rm -rf bin dist
