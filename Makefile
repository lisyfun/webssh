BINARY=webssh
APP=WebSSH.app

build:
	CGO_ENABLED=1 CGO_LDFLAGS="-framework UniformTypeIdentifiers" go build -tags "desktop,production" -o $(BINARY) .

run: build
	./$(BINARY)

package: build
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp build/darwin/Info.plist $(APP)/Contents/
	cp $(BINARY) $(APP)/Contents/MacOS/
	cp frontend/favicon.png $(APP)/Contents/Resources/iconfile.png
	codesign --force --deep --sign - $(APP)
	@echo "created $(APP)"

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	rm -rf $(APP)
	rm -rf build/bin/

.PHONY: build run package vet clean
