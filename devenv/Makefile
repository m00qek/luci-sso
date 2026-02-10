# --- 1. CONFIGURATION & EXPORTS ---
.ONESHELL: # Run recipes as single shell scripts
.SHELLFLAGS = -ec # Exit immediately on error

# Directory Resolution
DEVENV_DIR   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT := $(abspath $(DEVENV_DIR)/..)

# ANSI Color Codes
GREEN := \033[1;32m
BLUE  := \033[1;34m
YELLOW:= \033[1;33m
RED   := \033[1;31m
RESET := \033[0m

# Project Variables
export PKI_CURVE := prime256v1
export NODE_VERSION := 25
export ALPINE_VERSION := 3.23
export SDK_VERSION := 24.10.5
export SDK_ARCH    := x86-64
export CRYPTO_LIB  ?= mbedtls

# Dynamic Dependency Parsing from root Makefile
# Grab all DEPENDS lines, remove +, remove luci-sso*, and flatten into a unique sorted list
export PKG_DEPENDS := $(shell grep 'PKG_DEPENDS:=' $(PROJECT_ROOT)/Makefile | sed 's/PKG_DEPENDS:=//' | tr '+' ' ' | tr ' ' '\n' | sort -u | tr '\n' ' ')

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
export RESOLVED_DOCKER_COMPOSE = $(DEVENV_DIR)/.resolved.docker-compose.$(DOCKER_SUITE).yaml
COMPOSE_FLAGS = -p $(DOCKER_SUITE) -f $(DEVENV_DIR)/docker-compose.yaml -f $(DEVENV_DIR)/docker-compose.$(DOCKER_SUITE).yaml

# Helper: Returns container ID if any service in the suite is running
SUITE_IS_RUNNING = $(shell docker compose $(COMPOSE_FLAGS) ps -q 2>/dev/null)

# --- 3. PUBLIC INTERFACE ---
.PHONY: up e2e-up shell run e2e-shell e2e-run down e2e-down ps e2e-ps
.PHONY: build-images e2e-build-images compile unit-test e2e-test test package sync-headers

# Sentinel file tracks the last successful build
SENTINEL := $(PROJECT_ROOT)/bin/lib/.built

# Wrappers sets the context and calls the implementation
up: DOCKER_SUITE = local
up: .up

build-images: DOCKER_SUITE = local
build-images: .build-images

e2e-build-images: DOCKER_SUITE = e2e
e2e-build-images: .build-images

down: DOCKER_SUITE = local
down: .down

ps: DOCKER_SUITE = local
ps: .ps

shell: DOCKER_SUITE = local
shell: .shell

run: DOCKER_SUITE = local
run: .run

unit-test: DOCKER_SUITE = e2e
unit-test: .unit-test

e2e-test: DOCKER_SUITE = e2e
e2e-test: .e2e-test

test: unit-test e2e-test

# Watcher: Run tests automatically on change
watch-tests: DOCKER_SUITE = e2e
watch-tests: .watch-tests

# E2E Variants
e2e-up: DOCKER_SUITE = e2e
e2e-up: .up

e2e-shell: DOCKER_SUITE = e2e
e2e-shell: .shell

e2e-down: DOCKER_SUITE = e2e
e2e-down: .down

e2e-ps: DOCKER_SUITE = e2e
e2e-ps: .ps

unit-test: DOCKER_SUITE = e2e
unit-test: .unit-test

e2e-test: DOCKER_SUITE = e2e
e2e-test: .e2e-test

VAR ?= ""
print-env: 
	@echo "$${$(VAR)}"

# --- 4. IMPLEMENTATION (Private Targets) ---

# Macro: Abort if the current DOCKER_SUITE is not running
define VALIDATE_SUITE_RUNNING
	@if [ -z "$(SUITE_IS_RUNNING)" ]; then \
		echo -e " $(RED)⛔$(RESET) The '$(DOCKER_SUITE)' environment is NOT RUNNING."; \
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:$(RESET)"; \
		echo -e "\n      make $(if $(filter e2e,$(DOCKER_SUITE)),e2e-,)up"; \
		exit 1; \
	fi
endef

.unit-test:
	$(VALIDATE_SUITE_RUNNING)
	@$(DEVENV_DIR)/scripts/test.sh unit --modules "$(MODULES)" --filter "$(FILTER)"

.e2e-test:
	$(VALIDATE_SUITE_RUNNING)
	@$(DEVENV_DIR)/scripts/test.sh e2e --modules "$(MODULES)" --filter "$(FILTER)"

.watch-tests:
	$(VALIDATE_SUITE_RUNNING)
	@$(DEVENV_DIR)/scripts/test.sh watch --modules "$(MODULES)" --filter "$(FILTER)"

.build-images:
	@echo -e " $(BLUE)🔨$(RESET) Building images for '$(DOCKER_SUITE)'..."
	docker compose $(COMPOSE_FLAGS) build --pull=false

.up:
	@# VALIDATION: Check if already running
	@if [ -n "$(SUITE_IS_RUNNING)" ]; then
		echo -e " $(GREEN)✅$(RESET) The '$(DOCKER_SUITE)' environment is ALREADY RUNNING."
		echo -e " $(BLUE)ℹ️$(RESET)  Nothing to do."
		exit 0
	fi
	
	@echo -e " $(BLUE)⚙️$(RESET)  Generating configuration for '$(DOCKER_SUITE)'..."
	docker compose $(COMPOSE_FLAGS) config > $(RESOLVED_DOCKER_COMPOSE)
	
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
	$(VALIDATE_SUITE_RUNNING)
	
	@echo -e " $(BLUE)🐚$(RESET) Entering $(CONTAINER) ($(DOCKER_SUITE))..."
	docker compose $(COMPOSE_FLAGS) exec $(CONTAINER) /bin/sh

.run:
	$(VALIDATE_SUITE_RUNNING)
	
	@echo -e " $(BLUE)🐚$(RESET) Entering $(CONTAINER) ($(DOCKER_SUITE))..."
	docker compose $(COMPOSE_FLAGS) run -it --rm $(CONTAINER) /bin/sh

sync-headers:
	@echo -e " $(BLUE)🔄$(RESET) Syncing headers for LSP..."
	@mkdir -p $(DEVENV_DIR)/.include
	docker compose $(COMPOSE_FLAGS) run --rm sdk sh -c "cp -r /sdk/staging_dir/target-*/usr/include/* /sdk/package/luci-sso/devenv/.include/"

compile: $(SENTINEL)

$(SENTINEL): $(wildcard $(PROJECT_ROOT)/src/*.c) $(wildcard $(PROJECT_ROOT)/src/*.h) $(PROJECT_ROOT)/src/CMakeLists.txt
	@echo -e " $(BLUE)🔨$(RESET) Building native components for $(CRYPTO_LIB)..."
	@mkdir -p $(PROJECT_ROOT)/bin/lib
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh compile
	@touch $(SENTINEL)

package:
	@echo -e " $(BLUE)📦$(RESET) Building IPK package..."
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh package
