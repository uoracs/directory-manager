.PHONY: build install clean run container handler
all: build

build:
	@go build -o bin/directory-manager main.go

run: build
	@go run main.go

install: build
	@cp bin/directory-manager /usr/local/bin/directory-manager

handler:
	@go build -o handler main.go

clean:
	@rm -f bin/directory-manager /usr/local/bin/directory-manager
