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

# Architecture Resolution (Authoritative SDK Model)
# 1. Determine SDK_ARCH (Manual override > Host detection)
export SDK_ARCH ?= $(shell $(DEVENV_DIR)/scripts/resolve-arch.sh --host)

# 2. Derive ROOTFS_ARCH from SDK_ARCH
export ROOTFS_ARCH := $(shell $(DEVENV_DIR)/scripts/resolve-arch.sh $(SDK_ARCH))

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
export DOCKER_NAMESPACE := ghcr.io/m00qek

# Lazy variables (=) evaluated at runtime
export RESOLVED_DOCKER_COMPOSE = $(DEVENV_DIR)/.resolved.docker-compose.$(DOCKER_SUITE).yaml
# Use SDK_ARCH in project name to ensure isolated containers per architecture
COMPOSE_FLAGS = -p $(DOCKER_SUITE)-$(SDK_ARCH) -f $(DEVENV_DIR)/docker-compose.yaml -f $(DEVENV_DIR)/docker-compose.$(DOCKER_SUITE).yaml

# Helper: Returns container ID if any service in the suite is running
SUITE_IS_RUNNING = $(shell docker compose $(COMPOSE_FLAGS) ps -q 2>/dev/null)

# --- 3. PUBLIC INTERFACE ---
.PHONY: build-images up down ps shell run unit-test e2e-test test watch-tests
.PHONY: local-up local-down local-ps local-shell local-run

# Sentinel file tracks the last successful build for a specific arch/crypto combo
SENTINEL := $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/.built-$(CRYPTO_LIB)

# Wrappers sets the context and calls the implementation
local-up: DOCKER_SUITE = local
local-up: .up

local-down: DOCKER_SUITE = local
local-down: .down

local-run: DOCKER_SUITE = local
local-run: .run

local-shell: DOCKER_SUITE = local
local-shell: .shell

build-images: DOCKER_SUITE = ci
build-images: .build-images

up: DOCKER_SUITE = ci
up: .up

down: DOCKER_SUITE = ci
down: .down

ps: DOCKER_SUITE = ci
ps: .ps

shell: DOCKER_SUITE = ci
shell: .shell

run: DOCKER_SUITE = ci
run: .run

unit-test: DOCKER_SUITE = ci
unit-test: .unit-test

e2e-test: DOCKER_SUITE = ci
e2e-test: .ci-test

# Watcher: Run tests automatically on change
watch-tests: DOCKER_SUITE = ci
watch-tests: .watch-tests

test: unit-test e2e-test

VAR ?= ""
print-env: 
	@echo "$${$(VAR)}"

# --- 4. IMPLEMENTATION (Private Targets) ---

# Macro: Abort if the current DOCKER_SUITE is not running
define VALIDATE_SUITE_RUNNING
	@if [ -z "$(SUITE_IS_RUNNING)" ]; then \
		echo -e " $(RED)⛔$(RESET) The '$(DOCKER_SUITE)' environment is NOT RUNNING."; \
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:$(RESET)"; \
		echo -e "\n      make up"; \
		exit 1; \
	fi
endef

.unit-test:
	$(VALIDATE_SUITE_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(CRYPTO_LIB)
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh unit --modules "$(MODULES)" --filter "$(FILTER)"

.ci-test:
	$(VALIDATE_SUITE_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(CRYPTO_LIB)
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh ci --modules "$(MODULES)" --filter "$(FILTER)"

.watch-tests:
	$(VALIDATE_SUITE_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(CRYPTO_LIB)
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh watch --modules "$(MODULES)" --filter "$(FILTER)"

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
	@UP_FLAGS="--remove-orphans"; \
	if [ "$(DETACHED)" = "true" ]; then UP_FLAGS="$$UP_FLAGS -d"; fi; \
	docker compose $(COMPOSE_FLAGS) up $$UP_FLAGS
	
	@echo -e " $(GREEN)✨$(RESET) Done!$(RESET)"

.down:
	@echo -e " $(YELLOW)🛑$(RESET) Stopping '$(DOCKER_SUITE)' environment..."
	docker compose $(COMPOSE_FLAGS) down --remove-orphans

.ps:
	@docker compose $(COMPOSE_FLAGS) ps

CONTAINER ?= openwrt

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
	@echo -e " $(BLUE)🔨$(RESET) Building native components for $(SDK_ARCH)/$(CRYPTO_LIB)..."
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(CRYPTO_LIB)
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh compile
	@touch $(SENTINEL)

package:
	@echo -e " $(BLUE)📦$(RESET) Building IPK package for $(SDK_ARCH)..."
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/packages
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh package
