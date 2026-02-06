# LuCI SSO - Development Makefile
# This file orchestrates the dev environment, tests, and builds.

# --- Configuration (Single Source of Truth) ---
PKG_NAME    := luci-sso
SDK_VERSION := 24.10.5
SDK_ARCH    := x86-64
CRYPTO_LIB  ?= mbedtls
CRYPTO_LIBS := mbedtls wolfssl

# Export for Docker Compose
export SDK_VERSION
export CRYPTO_LIB

# Container Names
BUILDER_IMG := $(PKG_NAME)-builder:$(SDK_ARCH)-$(SDK_VERSION)
RUNNER_IMG  := luci-sso-tester-$(CRYPTO_LIB):$(SDK_ARCH)-$(SDK_VERSION)

WORK_DIR    := $(shell pwd)

.PHONY: all luci test prepare sync-headers compile-native package clean

all: test

# 1. Workflow: Start interactive development stack
luci: compile-native
	@echo "Starting LuCI SSO Dev Stack (OpenWrt $(SDK_VERSION))..."
	cd devenv && docker-compose up

# 2. Workflow: Run unit and integration tests
test: compile-native
	@echo "Running test suite ($(CRYPTO_LIB))..."
	@docker run --rm \
		-v "$(WORK_DIR):/app" \
		-e VERBOSE=$(VERBOSE) \
		$(RUNNER_IMG) \
		ucode -L /app/test/mocks \
		      -L /app/bin/lib/$(CRYPTO_LIB) \
		      -L /app/files/usr/share/ucode \
		      -L /app/test \
		      test/runner.uc

# 3. Setup: Prepare all containers (Using Sentinels for Caching)
prepare: devenv/.runner_built devenv/.builder_built

devenv/.builder_built: devenv/builder/Dockerfile
	@echo "Building SDK Builder (Warming up dependencies...)"
	docker build -t $(BUILDER_IMG) \
		--build-arg SDK_ARCH=$(SDK_ARCH) \
		--build-arg SDK_VERSION=$(SDK_VERSION) \
		-f devenv/builder/Dockerfile .
	@touch $@
	$(MAKE) -f dev.mk sync-headers

devenv/.runner_built: devenv/runner/Dockerfile devenv/runner/start-services.sh Makefile
	@for lib in $(CRYPTO_LIBS); do \
		echo "Building Runner ($$lib)..."; \
		DEPS="$$(grep 'DEPENDS:=' Makefile | head -n 1 | cut -d= -f2 | tr -d '+')"; \
		FILTERED_DEPS="$$(echo $$DEPS | tr ' ' '\n' | grep -v 'luci-sso' | tr '\n' ' ')"; \
		[ "$$lib" = "mbedtls" ] && FINAL_DEPS="$$FILTERED_DEPS libmbedtls" || FINAL_DEPS="$$FILTERED_DEPS libwolfssl"; \
		docker build -t luci-sso-tester-$$lib:$(SDK_ARCH)-$(SDK_VERSION) \
			--build-arg SDK_ARCH=$(SDK_ARCH) \
			--build-arg SDK_VERSION=$(SDK_VERSION) \
			--build-arg PKG_DEPENDS="$$FINAL_DEPS luci-light luci-mod-admin-full rpcd uhttpd luci-ssl openssl-util" \
			-f devenv/runner/Dockerfile . || exit 1; \
	done
	@touch $@

# 4. Utility: Sync headers for IDE/LSP support
sync-headers:
	@echo "Syncing headers from $(BUILDER_IMG)..."
	@mkdir -p devenv/.include
	@docker run --rm -v "$(WORK_DIR)/devenv/.include:/host_include" $(BUILDER_IMG) \
		sh -c "cp -r /sdk/staging_dir/target-*/usr/include/* /host_include/"

# 5. Build: Compile C extension inside the SDK
compile-native: bin/lib/.built

bin/lib/.built: $(wildcard src/*.c) src/CMakeLists.txt
	@echo "Compiling C extension for $(CRYPTO_LIB)..."
	@mkdir -p bin/lib/$(CRYPTO_LIB)/luci_sso
	@docker run --rm \
		-v "$(WORK_DIR):/sdk/package/$(PKG_NAME)" \
		-v "$(WORK_DIR)/bin/lib:/artifacts" \
		$(BUILDER_IMG) \
		sh -c " \
			[ -f .config ] || make defconfig && \
			make package/$(PKG_NAME)/compile QUICK=1 CHECK_KEY=0 IGNORE_ERRORS=m && \
			cp -v build_dir/target-*/$(PKG_NAME)-*/.pkgdir/$(PKG_NAME)-crypto-$(CRYPTO_LIB)/usr/lib/ucode/luci_sso/native.so /artifacts/$(CRYPTO_LIB)/luci_sso/native.so \
		"
	@touch bin/lib/.built

# 6. Packaging: Build final IPK
package:
	@mkdir -p bin
	@echo "Building OpenWrt package (.ipk)..."
	docker run --rm \
		-v "$(WORK_DIR):/sdk/package/$(PKG_NAME)" \
		-v "$(WORK_DIR)/bin:/sdk/bin" \
		$(BUILDER_IMG) \
		sh -c "make defconfig && make package/$(PKG_NAME)/compile V=s QUICK=1 CHECK_KEY=0"

clean:
	rm -rf bin/ devenv/.include/ devenv/.pki/ devenv/.*_built