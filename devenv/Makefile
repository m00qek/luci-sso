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
export UID := $(shell id -u)
export GID := $(shell id -g)
export PKI_CURVE := prime256v1
export NODE_VERSION := 25
export ALPINE_VERSION := 3.23
export SDK_VERSION := 24.10.5

# Architecture Resolution (Authoritative SDK Model)
# 1. Determine SDK_ARCH (Manual override > Host detection)
export SDK_ARCH := $(or $(SDK_ARCH),$(shell $(DEVENV_DIR)/scripts/resolve-arch.sh --host))

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

# Use SDK_ARCH and SDK_VERSION in project name to ensure isolated containers per environment
# We replace dots with hyphens because dots are invalid in Docker Compose project names
SAFE_SDK_VERSION = $(subst .,-,$(SDK_VERSION))

# Openwrt project: per SDK version, no DOCKER_SUITE prefix (suite differences handled by overlays)
COMPOSE_FLAGS = -p $(SDK_ARCH)-$(SAFE_SDK_VERSION) -f $(DEVENV_DIR)/docker-compose.yaml -f $(DEVENV_DIR)/docker-compose.$(DOCKER_SUITE).yaml

# Infra project: fixed name, shared across all OpenWrt versions
INFRA_COMPOSE_FLAGS = -p luci-sso-infra -f $(DEVENV_DIR)/docker-compose.infra.yaml -f $(DEVENV_DIR)/docker-compose.infra.$(DOCKER_SUITE).yaml

# Helper: Command to return container IDs if any service in the openwrt project is running
SUITE_IS_RUNNING_CMD = docker compose $(COMPOSE_FLAGS) ps -q 2>/dev/null

# Helper: Command to check if the shared infra idp is running
INFRA_IS_RUNNING_CMD = docker compose $(INFRA_COMPOSE_FLAGS) ps -q idp 2>/dev/null

# --- 3. PUBLIC INTERFACE ---
.PHONY: build-images up down ps shell run infra-up infra-down test fuzz e2e watch-tests lint pull

# Sentinel file tracks the last successful build for a specific arch/version/crypto combo
SENTINEL := $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/.built-$(CRYPTO_LIB)

build-images: .build-images
up: .up
down: .down
ps: .ps
shell: .shell
run: .run
pull: .pull
infra-up: .infra-up
infra-down: .infra-down

test: DOCKER_SUITE = ci
test: .unit-test

fuzz: DOCKER_SUITE = ci
fuzz: .fuzzer-test

e2e: DOCKER_SUITE = ci
e2e: .e2e-test

watch-tests: DOCKER_SUITE = ci
watch-tests: .watch-tests

lint:
	@echo -e " $(BLUE)🔍$(RESET) Running documentation lint checks..."
	@bash $(DEVENV_DIR)/scripts/check-error-codes.sh
	@bash $(DEVENV_DIR)/scripts/check-request-limits.sh
	@bash $(DEVENV_DIR)/scripts/check-cookie-names.sh
	@echo -e " $(GREEN)✅$(RESET) All lint checks passed."

VAR ?= ""
print-env:
	@echo "$${$(VAR)}"

.pull:
	@docker compose $(INFRA_COMPOSE_FLAGS) pull
	@docker compose $(COMPOSE_FLAGS) pull

# --- 4. IMPLEMENTATION (Private Targets) ---

# Macro: Abort if the openwrt project is not running
define VALIDATE_SUITE_RUNNING
	@if [ -z "$$($(SUITE_IS_RUNNING_CMD))" ]; then \
		echo -e " $(RED)⛔$(RESET) The '$(DOCKER_SUITE)' environment is NOT RUNNING."; \
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:"; \
		echo -e "\n      make up"; \
		exit 1; \
	fi
endef

# Macro: Abort if shared infra is not running
define VALIDATE_INFRA_RUNNING
	@if [ -z "$$($(INFRA_IS_RUNNING_CMD))" ]; then \
		echo -e " $(RED)⛔$(RESET) Infrastructure is NOT RUNNING."; \
		echo -e " $(BLUE)ℹ️$(RESET)  Please start it first:"; \
		echo -e "\n      make infra-up DOCKER_SUITE=ci"; \
		exit 1; \
	fi
endef

.infra-up:
	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(INFRA_COMPOSE_FLAGS) pull || true
	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(INFRA_COMPOSE_FLAGS) build
	@echo -e " $(GREEN)🚀$(RESET) Starting infrastructure..."
	docker compose $(INFRA_COMPOSE_FLAGS) up -d --wait --remove-orphans
	@echo -e " $(GREEN)✨$(RESET) Done!"

.infra-down:
	@echo -e " $(YELLOW)🛑$(RESET) Stopping infrastructure..."
	docker compose $(INFRA_COMPOSE_FLAGS) down --remove-orphans

.unit-test:
	$(VALIDATE_INFRA_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" INFRA_COMPOSE_FLAGS="$(INFRA_COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh unit --modules "$(MODULES)" --filter "$(FILTER)"

TIME ?= 60
DETECT_LEAKS ?= 0

.fuzzer-test:
	@echo -e " $(BLUE)🧪$(RESET) Running native fuzz tests for $(CRYPTO_LIB) ($(TIME)s)..."
	docker compose $(COMPOSE_FLAGS) pull fuzzer || true
	docker compose $(COMPOSE_FLAGS) run --rm -e ASAN_OPTIONS="detect_leaks=$(DETECT_LEAKS)" fuzzer bash -c " \
		mkdir -p bin/fuzz && cd bin/fuzz && \
		cmake -DENABLE_FUZZING=ON ../../src && \
		make -j$$(nproc) && \
		./fuzz_$(CRYPTO_LIB) -max_total_time=$(TIME) -rss_limit_mb=2048"

.e2e-test:
	$(VALIDATE_INFRA_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" INFRA_COMPOSE_FLAGS="$(INFRA_COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh e2e --modules "$(MODULES)" --filter "$(FILTER)"

.watch-tests:
	$(VALIDATE_INFRA_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" INFRA_COMPOSE_FLAGS="$(INFRA_COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh watch --modules "$(MODULES)" --filter "$(FILTER)"

.build-images:
	@echo -e " $(BLUE)🔨$(RESET) Building images..."
	docker compose $(INFRA_COMPOSE_FLAGS) build --pull=false
	docker compose $(COMPOSE_FLAGS) build --pull=false

.up:
	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(INFRA_COMPOSE_FLAGS) pull || true
	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(INFRA_COMPOSE_FLAGS) build
	docker compose $(INFRA_COMPOSE_FLAGS) up -d --wait --remove-orphans

	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(COMPOSE_FLAGS) pull || true
	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(COMPOSE_FLAGS) build
	@echo -e " $(GREEN)🚀$(RESET) Starting '$(DOCKER_SUITE)' environment..."
	docker compose $(COMPOSE_FLAGS) up -d --wait --remove-orphans openwrt

	@echo -e " $(GREEN)✨$(RESET) Done!"

.down:
	@echo -e " $(YELLOW)🛑$(RESET) Stopping '$(DOCKER_SUITE)' environment..."
	docker compose $(COMPOSE_FLAGS) down --remove-orphans
	docker compose $(INFRA_COMPOSE_FLAGS) down --remove-orphans

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
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh compile

	@touch $(SENTINEL)

package:
	@echo -e " $(BLUE)📦$(RESET) Building IPK package for $(SDK_ARCH)..."
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/packages
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION) 2>/dev/null || true
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh package
