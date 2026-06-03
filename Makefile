BINARY=webssh
APP=WebSSH.app
DMG=WebSSH.dmg
RELEASE_DIR=release

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

release: package
	rm -rf $(RELEASE_DIR)
	mkdir -p $(RELEASE_DIR)
	ARCH=$$(uname -m); \
	if command -v create-dmg >/dev/null 2>&1; then \
		create-dmg --volname "WebSSH" \
			--window-pos 200 120 --window-size 800 400 \
			--icon-size 100 --icon "WebSSH.app" 200 190 \
			--hide-extension "WebSSH.app" \
			--app-drop-link 600 185 \
			"$(RELEASE_DIR)/$(DMG)" "$(APP)" && dmg_create=true; \
	fi; \
	if [ "$$dmg_create" != "true" ]; then \
		tar czf "$(RELEASE_DIR)/webssh-$$ARCH.tar.gz" "$(APP)"; \
		echo "create-dmg not found, created tar.gz instead"; \
	fi; \
	cp -r "$(APP)" "$(RELEASE_DIR)/"
	@echo "created release in $(RELEASE_DIR)/"

# Build universal binary (arm64 + amd64) and package as .app
universal:
	@echo "Building for arm64..."
	CGO_ENABLED=1 CGO_LDFLAGS="-framework UniformTypeIdentifiers" \
		go build -tags "desktop,production" -o $(BINARY)-arm64 .
	@echo "Building for amd64..."
	CGO_ENABLED=1 GOARCH=amd64 CGO_LDFLAGS="-framework UniformTypeIdentifiers" \
		go build -tags "desktop,production" -o $(BINARY)-amd64 .
	@echo "Creating universal binary..."
	lipo -create -output $(BINARY) $(BINARY)-arm64 $(BINARY)-amd64
	rm -f $(BINARY)-arm64 $(BINARY)-amd64
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp build/darwin/Info.plist $(APP)/Contents/
	cp $(BINARY) $(APP)/Contents/MacOS/
	cp frontend/favicon.png $(APP)/Contents/Resources/iconfile.png
	codesign --force --deep --sign - $(APP)
	@echo "created universal $(APP)"

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	rm -rf $(APP)
	rm -rf $(RELEASE_DIR)
	rm -rf build/bin/

.PHONY: build run package release vet clean
