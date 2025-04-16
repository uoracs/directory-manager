.PHONY: build install clean run container handler
all: build

build:
	@go build -o bin/directory-manager cmd/directory-manager/main.go

run: build
	@go run cmd/directory-manager/main.go

install: build
	@cp bin/directory-manager /usr/local/bin/directory-manager

handler:
	@go build -o handler cmd/directory-manager/main.go

clean:
	@rm -f bin/directory-manager /usr/local/bin/directory-manager
