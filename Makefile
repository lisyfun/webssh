BINARY=webssh

build:
	go build -o $(BINARY) .

vet:
	go vet ./...

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)

.PHONY: build vet run clean
