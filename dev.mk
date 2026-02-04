# Extract metadata from Makefile
PKG_NAME := $(shell grep '^PKG_NAME:=' Makefile | cut -d= -f2)
PKG_DEPENDS := $(shell grep 'DEPENDS:=' Makefile | cut -d= -f2 | tr -d '+' | tr '\n' ' ' | sed 's/$(PKG_NAME)[^ ]*//g')

# Development Environment Configuration
SDK_VERSION := 24.10.5
SDK_ARCH := x86-64
CRYPTO_LIBS := mbedtls wolfssl
CRYPTO_LIB ?= mbedtls

BUILDER_IMAGE := $(PKG_NAME)-builder:$(SDK_ARCH)-$(SDK_VERSION)
RUNNER_IMAGE_BASE := $(PKG_NAME)-tester
RUNNER_IMAGE := $(RUNNER_IMAGE_BASE)-$(CRYPTO_LIB):$(SDK_ARCH)-$(SDK_VERSION)

WORK_DIR := $(shell pwd)

.PHONY: all prepare test watch-tests package clean

all: test

prepare:
	echo "Building packaging container for $(SDK_ARCH)-$(SDK_VERSION)..."
	docker build -t $(BUILDER_IMAGE) \
		--build-arg SDK_ARCH=$(SDK_ARCH) \
		--build-arg SDK_VERSION=$(SDK_VERSION) \
		-f Dockerfile .
	for lib in $(CRYPTO_LIBS); do \
		echo "Building development container for $(SDK_ARCH)-$(SDK_VERSION) with $$lib..."; \
		docker build -t $(RUNNER_IMAGE_BASE)-$$lib:$(SDK_ARCH)-$(SDK_VERSION) \
			--build-arg SDK_ARCH=$(SDK_ARCH) \
			--build-arg SDK_VERSION=$(SDK_VERSION) \
			--build-arg PKG_DEPENDS="$(sort $(PKG_DEPENDS))" \
			-f Dockerfile.dev . || exit 1; \
	done
	$(MAKE) -f dev.mk sync-headers

sync-headers:
	@echo "Syncing headers from $(BUILDER_IMAGE)..."
	@mkdir -p .include
	@docker run --rm -v "$(WORK_DIR)/.include:/host_include" $(BUILDER_IMAGE) \
		sh -c "cp -r /sdk/staging_dir/target-*/usr/include/* /host_include/"
	@echo "Headers synced to .include/"

test: compile-native
	@docker run --rm \
		-v "$(WORK_DIR):/app" \
		-e VERBOSE=$(VERBOSE) \
		$(RUNNER_IMAGE) \
		ucode -L /app/test/mocks -L /app/bin/lib/$(CRYPTO_LIB) -L /app/files/usr/share/ucode -L /app/test test/runner.uc

SOURCES := $(wildcard src/*.c)

# Sentinel file to track build status
bin/lib/.built: $(SOURCES) src/CMakeLists.txt
	@echo "Source changed, compiling C extension(s) in SDK..."
	@mkdir -p bin/lib/$(CRYPTO_LIB)/luci_sso
	@chmod -R 777 bin/lib
	@docker run --rm \
		-v "$(WORK_DIR):/sdk/package/$(PKG_NAME)" \
		-v "$(WORK_DIR)/bin/lib:/artifacts" \
		$(BUILDER_IMAGE) \
		sh -c "make package/$(PKG_NAME)/compile V=s && \
		       echo 'Build finished, copying artifacts...' && \
		       mkdir -p /artifacts/$(CRYPTO_LIB)/luci_sso && \
		       cp -v build_dir/target-*/$(PKG_NAME)-1.0.0/.pkgdir/$(PKG_NAME)-crypto-$(CRYPTO_LIB)/usr/lib/ucode/luci_sso/native.so /artifacts/$(CRYPTO_LIB)/luci_sso/native.so && \
		       ls -l /artifacts/$(CRYPTO_LIB)/luci_sso/native.so"
	@touch bin/lib/.built

compile-native: bin/lib/.built

debug: compile-native
	@echo "Starting debug shell..."
	@docker run --rm -it \
		-v "$(WORK_DIR):/app" \
		-e VERBOSE=$(VERBOSE) \
		$(RUNNER_IMAGE) \
		/bin/sh

watch-tests:
	@echo "Watching for changes using entr..."
	@find src test files -type f 2>/dev/null | entr -c -r $(MAKE) -f dev.mk test

package:
	@mkdir -p bin
	@chmod 777 bin
	@echo "Building IPK for $(SDK_ARCH) using $(BUILDER_IMAGE)..."
	docker run --rm \
		-v "$(WORK_DIR):/sdk/package/$(PKG_NAME)" \
		-v "$(WORK_DIR)/bin:/sdk/bin" \
		$(BUILDER_IMAGE) \
		sh -c "make defconfig && make package/$(PKG_NAME)/compile V=s"
	@echo "Package build complete. Check the 'bin' directory for the .ipk file."

clean:
	@rm -rf bin/
