BINARY=webssh
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

build:
	go build -o $(BINARY) .

build-all:
	@for p in $(PLATFORMS); do \
		os=$$(echo $$p | cut -d/ -f1); \
		arch=$$(echo $$p | cut -d/ -f2); \
		suffix=$$os-$$arch; \
		[ $$os = windows ] && suffix=$$suffix.exe; \
		echo "building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build -o release/$(BINARY)-$$suffix .; \
	done
	@echo "all done, see release/"

vet:
	go vet ./...

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)
	rm -rf release/

.PHONY: build build-all vet run clean
