.PHONY: test
test:
	go test -v ./...

.PHONY: cover
cover:
	go test -coverprofile=bin/cover.out ./pkcs11
	go tool cover -html=bin/cover.out
