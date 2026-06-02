BINARY=webssh
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

build:
	go build -o $(BINARY) .

build-all:
	@mkdir -p release
	@for p in $(PLATFORMS); do \
		os=$$(echo $$p | cut -d/ -f1); \
		arch=$$(echo $$p | cut -d/ -f2); \
		suffix=$$os-$$arch; \
		echo "building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build -o release/$(BINARY)-$$suffix .; \
	done
	@echo "all done, see release/"

release: build-all
	@mkdir -p dist
	cp README.md release/
	@for f in release/webssh-*; do \
		name=$$(basename $$f); \
		echo "packing $$name..."; \
		tar czf dist/$$name.tar.gz -C release $$name README.md; \
	done
	rm release/README.md
	@echo ""
	@echo "packages in dist/:"
	@ls -lh dist/

vet:
	go vet ./...

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)
	rm -rf release/ dist/

.PHONY: build build-all release vet run clean
