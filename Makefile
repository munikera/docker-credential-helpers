PACKAGE ?= github.com/docker/docker-credential-helpers
VERSION ?= $(shell ./hack/git-meta version)
REVISION ?= $(shell ./hack/git-meta revision)

GO_PKG = github.com/docker/docker-credential-helpers
GO_LDFLAGS = -s -w -X ${GO_PKG}/credentials.Version=${VERSION} -X ${GO_PKG}/credentials.Revision=${REVISION} -X ${GO_PKG}/credentials.Package=${PACKAGE}

BUILDX_CMD ?= docker buildx
DESTDIR ?= ./bin/build

.PHONY: all
all: cross

.PHONY: clean
clean:
	rm -rf bin

.PHONY: build-%
# Attached .exe tail when making wincred file
build-wincred: # build-wincred only
	go build -trimpath -ldflags="$(GO_LDFLAGS) -X ${GO_PKG}/credentials.Name=docker-credential-wincred" -o "$(DESTDIR)/docker-credential-wincred.exe" ./wincred/cmd/

build-%: # build, can be one of build-osxkeychain build-pass build-secretservice build-wincred
	go build -trimpath -ldflags="$(GO_LDFLAGS) -X ${GO_PKG}/credentials.Name=docker-credential-$*" -o "$(DESTDIR)/docker-credential-$*.exe" ./$*/cmd/

# aliases for build-* targets
.PHONY: osxkeychain secretservice pass wincred
osxkeychain: build-osxkeychain
secretservice: build-secretservice
pass: build-pass
wincred: build-wincred

.PHONY: cross
cross: # cross build all supported credential helpers
	$(BUILDX_CMD) bake binaries

.PHONY: release
release: # create release
	./hack/release

.PHONY: test
test: # tests all packages except vendor
	go test -v `go list ./... | grep -v /vendor/`

.PHONY: lint
lint:
	$(BUILDX_CMD) bake lint

.PHONY: validate-vendor
validate-vendor:
	$(BUILDX_CMD) bake vendor-validate

.PHONY: fmt
fmt:
	gofmt -s -l `ls **/*.go | grep -v vendor`

.PHONY: validate
validate: lint validate-vendor fmt

BUILDIMG:=docker-credential-secretservice-$(VERSION)
.PHONY: deb
deb:
	mkdir -p release
	docker build -f deb/Dockerfile \
		--build-arg VERSION=$(patsubst v%,%,$(VERSION)) \
		--build-arg REVISION=$(REVISION) \
		--tag $(BUILDIMG) \
		.
	docker run --rm --net=none $(BUILDIMG) tar cf - /release | tar xf -
	docker rmi $(BUILDIMG)

.PHONY: vendor
vendor:
	$(eval $@_TMP_OUT := $(shell mktemp -d -t docker-output.XXXXXXXXXX))
	$(BUILDX_CMD) bake --set "*.output=type=local,dest=$($@_TMP_OUT)" vendor
	rm -rf ./vendor
	cp -R "$($@_TMP_OUT)"/* .
	rm -rf "$($@_TMP_OUT)"
