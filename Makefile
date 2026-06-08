BINARY=webssh
APP=WebSSH.app
DMG=WebSSH.dmg
RELEASE_DIR=release

# macOS-specific linker flags (detect via uname)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
CGO_LDFLAGS = -framework UniformTypeIdentifiers
endif

build:
	CGO_ENABLED=1 CGO_LDFLAGS="$(CGO_LDFLAGS)" go build -tags "desktop,production" -o $(BINARY) .

icons-windows: frontend/favicon.png
	convert frontend/favicon.png -define icon:auto-resize=256,64,48,32,16 frontend/favicon.ico
	go run ./tools/gen_windows_icon.go

build-windows: icons-windows
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
		CC=x86_64-w64-mingw32-gcc \
		CXX=x86_64-w64-mingw32-g++ \
		CGO_LDFLAGS="" \
		go build -tags "desktop,production" -ldflags="-H=windowsgui" -o $(BINARY).exe .

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
		CGO_LDFLAGS="" \
		go build -tags "desktop,production" -o $(BINARY)-linux .

# 统信OS / Linux .deb 打包
deb: build-linux
	@echo "Building .deb package for UOS/Linux..."
	# 复制二进制
	cp $(BINARY)-linux build/debian/usr/bin/$(BINARY)
	# 设置权限
	chmod 755 build/debian/usr/bin/$(BINARY)
	chmod 755 build/debian/DEBIAN/postinst
	chmod 755 build/debian/DEBIAN/prerm
	# 生成 deb 包
	dpkg-deb --build build/debian ./$(BINARY)-uos-amd64.deb
	@echo "Package created: $(BINARY)-uos-amd64.deb"
	# 清理
	rm -f build/debian/usr/bin/$(BINARY)

build-uos: deb
	@echo "UOS package built successfully"

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
	CGO_ENABLED=1 CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		go build -tags "desktop,production" -o $(BINARY)-arm64 .
	@echo "Building for amd64..."
	CGO_ENABLED=1 GOARCH=amd64 CGO_LDFLAGS="$(CGO_LDFLAGS)" \
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
	rm -f $(BINARY).exe
	rm -f $(BINARY)-linux
	rm -f $(BINARY)-uos-amd64.deb
	rm -f rsrc_windows_*.syso
	rm -f frontend/favicon.ico
	rm -rf winres/
	rm -rf $(APP)
	rm -rf $(RELEASE_DIR)
	rm -rf build/bin/

.PHONY: build build-windows build-linux build-uos deb run package release universal vet clean
