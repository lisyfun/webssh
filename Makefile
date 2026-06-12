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
	go build -ldflags="-s -w" -o $(BINARY) .

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY).exe .

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-linux .

# 统信OS 20 (Debian 10) .deb 打包（需要本机 Linux + GTK/WebKit dev libs）
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

# 统信OS .deb + 离线依赖包（使用 Docker，无需 Linux 机器）
uos-docker:
	@echo "Building UOS .deb with Docker (works on macOS/Linux)..."
	bash build/build_uos_docker.sh

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
