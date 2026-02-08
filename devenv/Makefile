# --- 1. CONFIGURATION & EXPORTS ---
.ONESHELL: # Run recipes as single shell scripts
.SHELLFLAGS = -ec # Exit immediately on error

# ANSI Color Codes
GREEN := \033[1;32m
BLUE  := \033[1;34m
YELLOW:= \033[1;33m
RED   := \033[1;31m
RESET := \033[0m

# Project Variables
export PKI_CURVE := prime256v1
export NODE_VERSION := 25
export SDK_VERSION := 24.10.5
export SDK_ARCH    := x86-64
export CRYPTO_LIB  ?= mbedtls

# Dynamic Dependency Parsing from root Makefile
# Grab all DEPENDS lines, remove +, remove luci-sso*, and flatten into a unique sorted list
export PKG_DEPENDS := $(shell grep 'DEPENDS:=' ../Makefile | sed 's/DEPENDS:=//' | tr '+' ' ' | tr ' ' '\n' | grep -v 'luci-sso' | sort -u | tr '\n' ' ')

export DOMAIN := luci-sso.test
export FQDN_IDP := idp.$(DOMAIN)
export FQDN_LUCI := luci.$(DOMAIN)
export FQDN_BROWSER := browser.$(DOMAIN)

export PORT_IDP := 5556
export PORT_LUCI := 8443

# --- 2. DYNAMIC SUITE CONFIG ---
# Default to local if not set
export DOCKER_SUITE ?= local

# Lazy variables (=) evaluated at runtime
export RESOLVED_DOCKER_COMPOSE = .resolved.docker-compose.$(DOCKER_SUITE).yaml
COMPOSE_FLAGS = -p $(DOCKER_SUITE) -f docker-compose.yaml -f docker-compose.$(DOCKER_SUITE).yaml

# Helper: Returns container ID if any service in the suite is running
SUITE_IS_RUNNING = $(shell docker compose $(COMPOSE_FLAGS) ps -q 2>/dev/null)

# --- 3. PUBLIC INTERFACE ---
.PHONY: up e2e-up shell run e2e-shell e2e-run down e2e-down ps e2e-ps
.PHONY: compile unit-test package sync-headers

# Sentinel file tracks the last successful build
SENTINEL := ../bin/lib/.built

# Wrappers sets the context and calls the implementation
up: DOCKER_SUITE = local
up: .up

down: DOCKER_SUITE = local
down: .down

ps: DOCKER_SUITE = local
ps: .ps

shell: DOCKER_SUITE = local
shell: .shell

run: DOCKER_SUITE = local
run: .run

# SDK / Build targets
compile: DOCKER_SUITE = local
compile: .compile

unit-test: DOCKER_SUITE = e2e
unit-test: .unit-test

package: DOCKER_SUITE = local
package: .package

sync-headers: DOCKER_SUITE = local
sync-headers: .sync-headers

# E2E Variants
e2e-up: DOCKER_SUITE = e2e
e2e-up: .up

e2e-shell: DOCKER_SUITE = e2e
e2e-shell: .shell

e2e-down: DOCKER_SUITE = e2e
e2e-down: .down

e2e-ps: DOCKER_SUITE = e2e
e2e-ps: .ps

e2e-test: DOCKER_SUITE = e2e
e2e-test: .e2e-test

e2e-run: DOCKER_SUITE = e2e
e2e-run: .run

# --- 4. IMPLEMENTATION (Private Targets) ---
.up:
	@# VALIDATION: Check if already running
	@if [ -n "$(SUITE_IS_RUNNING)" ]; then
		echo -e " $(GREEN)✅$(RESET) The '$(DOCKER_SUITE)' environment is ALREADY RUNNING."
		echo -e " $(BLUE)ℹ️$(RESET)  Nothing to do. To stop it, run:$(RESET)"
		echo -e "\n      make $(if $(filter e2e,$(DOCKER_SUITE)),e2e-,)down"
		exit 0
	fi
	
	@echo -e " $(BLUE)⚙️$(RESET)  Generating configuration for '$(DOCKER_SUITE)'..."
	docker compose $(COMPOSE_FLAGS) config > $(RESOLVED_DOCKER_COMPOSE)
	
	@echo -e " $(BLUE)🔨$(RESET) Building images (Quietly)..."
	docker compose $(COMPOSE_FLAGS) build
	
	@echo -e " $(GREEN)🚀$(RESET) Starting '$(DOCKER_SUITE)' environment..."
	docker compose $(COMPOSE_FLAGS) up --remove-orphans
	
	@echo -e " $(GREEN)✨$(RESET) Done!$(RESET)"

.down:
	@echo -e " $(YELLOW)🛑$(RESET) Stopping '$(DOCKER_SUITE)' environment..."
	docker compose $(COMPOSE_FLAGS) down --remove-orphans

.ps:
	@docker compose $(COMPOSE_FLAGS) ps

CONTAINER ?= luci

.shell:
	@# VALIDATION: Ensure it is running before trying to connect
	@if [ -z "$(SUITE_IS_RUNNING)" ]; then
		echo -e " $(RED)⛔$(RESET) The '$(DOCKER_SUITE)' environment is NOT RUNNING."
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:$(RESET)"
		echo -e "\n      make $(if $(filter e2e,$(DOCKER_SUITE)),e2e-,)up"
		exit 1
	fi
	
	@echo -e " $(BLUE)🐚$(RESET) Entering $(CONTAINER) ($(DOCKER_SUITE))..."
	docker compose $(COMPOSE_FLAGS) exec $(CONTAINER) /bin/sh

.run:
	@# VALIDATION: Ensure it is running before trying to connect
	@if [ -z "$(SUITE_IS_RUNNING)" ]; then
		echo -e " $(RED)⛔$(RESET) The '$(DOCKER_SUITE)' environment is NOT RUNNING."
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:$(RESET)"
		echo -e "\n      make $(if $(filter e2e,$(DOCKER_SUITE)),e2e-,)up"
		exit 1
	fi
	
	@echo -e " $(BLUE)🐚$(RESET) Entering $(CONTAINER) ($(DOCKER_SUITE))..."
	docker compose $(COMPOSE_FLAGS) run -it --rm $(CONTAINER) /bin/sh

.e2e-test:
	@# VALIDATION: Ensure it is running
	@if [ -z "$(SUITE_IS_RUNNING)" ]; then
		echo -e " $(RED)⛔$(RESET) The '$(DOCKER_SUITE)' environment is NOT RUNNING."
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:$(RESET)"
		echo -e "\n      make e2e-up"
		exit 1
	fi
	
	@echo -e " $(GREEN)🧪$(RESET) Running E2E tests in browser container..."
	docker compose $(COMPOSE_FLAGS) exec browser npx playwright test

.compile: $(SENTINEL)

$(SENTINEL): $(wildcard ../src/*.c) $(wildcard ../src/*.h) ../src/CMakeLists.txt
	@echo -e " $(BLUE)🔨$(RESET) Building native components for $(CRYPTO_LIB)..."
	@mkdir -p ../bin/lib
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh compile
	@touch $(SENTINEL)

.unit-test:
	@# VALIDATION: Ensure it is running
	@if [ -z "$(SUITE_IS_RUNNING)" ]; then
		echo -e " $(RED)⛔$(RESET) The '$(DOCKER_SUITE)' environment is NOT RUNNING."
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:$(RESET)"
		echo -e "\n      make e2e-up"
		exit 1
	fi
	
	@echo -e " $(GREEN)🧪$(RESET) Running unit tests in luci container..."
	docker compose $(COMPOSE_FLAGS) exec luci ucode \
		-L /usr/share/ucode \
		-L /usr/lib/ucode \
		-L /usr/share/ucode/luci_sso \
		-L /usr/share/luci-sso/test/mocks \
		-L /usr/share/luci-sso/test \
		/usr/share/luci-sso/test/runner.uc

.package:
	@echo -e " $(BLUE)📦$(RESET) Building IPK package..."
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh package

.sync-headers:
	@echo -e " $(BLUE)🔄$(RESET) Syncing headers for LSP..."
	@mkdir -p .include
	docker compose $(COMPOSE_FLAGS) run --rm sdk sh -c "cp -r /sdk/staging_dir/target-*/usr/include/* /sdk/package/luci-sso/devenv/.include/"
