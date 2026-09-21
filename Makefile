# --- 1. CONFIGURATION & EXPORTS ---
.ONESHELL: # Run recipes as single shell scripts
.SHELLFLAGS = -ec # Exit immediately on error

# Directory Resolution
PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DEVENV_DIR   := $(PROJECT_ROOT)/devenv

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
export PKG_DEPENDS := $(shell grep 'PKG_DEPENDS:=' $(PROJECT_ROOT)/openwrt/luci-sso/Makefile | sed 's/PKG_DEPENDS:=//' | tr '+' ' ' | tr ' ' '\n' | sort -u | tr '\n' ' ')

export DOMAIN := luci-sso.test
export FQDN_IDP := idp.$(DOMAIN)
export FQDN_LUCI := luci.$(DOMAIN)
export FQDN_BROWSER := browser.$(DOMAIN)

export PORT_IDP := 5556
export PORT_LUCI := 8443

# --- 2. DYNAMIC SUITE CONFIG ---
export DOCKER_SUITE ?= local
export DOCKER_NAMESPACE := ghcr.io/m00qek

# Lazy variables (=) evaluated at runtime
export RESOLVED_DOCKER_COMPOSE = $(DEVENV_DIR)/.resolved.docker-compose.$(DOCKER_SUITE).yaml
# We replace dots with hyphens because dots are invalid in Docker Compose project names
SAFE_SDK_VERSION = $(subst .,-,$(SDK_VERSION))
COMPOSE_FLAGS = -p $(DOCKER_SUITE)-$(SDK_ARCH)-$(SAFE_SDK_VERSION) -f $(DEVENV_DIR)/docker-compose.yaml -f $(DEVENV_DIR)/docker-compose.$(DOCKER_SUITE).yaml

# Helper: Command to return container IDs if any service in the suite is running
# We use --all to ensure we detect the project even if one-shot services (pki) have exited
# This is a raw string, NOT wrapped in $(shell), so it's evaluated at recipe runtime.
SUITE_IS_RUNNING_CMD = docker compose $(COMPOSE_FLAGS) ps -a -q 2>/dev/null

# --- 3. PUBLIC INTERFACE ---
.PHONY: build-images up down ps shell run unit-test e2e-test test watch-tests lint
.PHONY: local-up local-down local-ps local-shell local-run

# Sentinel file tracks the last successful build for a specific arch/version/crypto combo
SENTINEL := $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/.built-$(CRYPTO_LIB)

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

fuzzer-test: DOCKER_SUITE = ci
fuzzer-test: .fuzzer-test

e2e-test: DOCKER_SUITE = ci
e2e-test: .e2e-test

watch-tests: DOCKER_SUITE = ci
watch-tests: .watch-tests

test: unit-test e2e-test

lint:
	@bash $(DEVENV_DIR)/scripts/check-error-codes.sh
	@bash $(DEVENV_DIR)/scripts/check-request-limits.sh
	@bash $(DEVENV_DIR)/scripts/check-cookie-names.sh

pull: DOCKER_SUITE = ci
pull: .pull

VAR ?= ""
print-env:
	@echo "$${$(VAR)}"

.pull:
	@docker compose $(COMPOSE_FLAGS) pull

# --- 4. IMPLEMENTATION (Private Targets) ---

define VALIDATE_SUITE_RUNNING
	@if [ -z "$$($(SUITE_IS_RUNNING_CMD))" ]; then \
		echo "Error: '$(DOCKER_SUITE)' environment is not running. Start it with: make up"; \
		exit 1; \
	fi
endef

.unit-test:
	$(VALIDATE_SUITE_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh unit --modules "$(MODULES)" --filter "$(FILTER)"

TIME ?= 60
DETECT_LEAKS ?= 0

.fuzzer-test:
	docker compose $(COMPOSE_FLAGS) pull fuzzer || true
	docker compose $(COMPOSE_FLAGS) run --rm -e ASAN_OPTIONS="detect_leaks=$(DETECT_LEAKS)" fuzzer bash -c " \
		mkdir -p bin/fuzz && cd bin/fuzz && \
		cmake -DENABLE_FUZZING=ON ../../mod && \
		make -j$$(nproc) && \
		./fuzz_$(CRYPTO_LIB) -max_total_time=$(TIME) -rss_limit_mb=2048"

.e2e-test:
	$(VALIDATE_SUITE_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh e2e --modules "$(MODULES)" --filter "$(FILTER)"

.watch-tests:
	$(VALIDATE_SUITE_RUNNING)
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" $(DEVENV_DIR)/scripts/test.sh watch --modules "$(MODULES)" --filter "$(FILTER)"

.build-images:
	docker compose $(COMPOSE_FLAGS) build --pull=false

.up:
	@if [ -n "$$($(SUITE_IS_RUNNING_CMD))" ]; then \
		echo "'$(DOCKER_SUITE)' environment is already running."; \
		exit 0; \
	fi
	docker compose $(COMPOSE_FLAGS) config > $(RESOLVED_DOCKER_COMPOSE)
	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(COMPOSE_FLAGS) pull || true
	@[ "$(GITHUB_ACTIONS)" != "true" ] && docker compose $(COMPOSE_FLAGS) build
	docker compose $(COMPOSE_FLAGS) up --remove-orphans -d

.down:
	docker compose $(COMPOSE_FLAGS) down --remove-orphans

.ps:
	@docker compose $(COMPOSE_FLAGS) ps

CONTAINER ?= openwrt

.shell:
	$(VALIDATE_SUITE_RUNNING)
	docker compose $(COMPOSE_FLAGS) exec $(CONTAINER) /bin/sh

.run:
	$(VALIDATE_SUITE_RUNNING)
	docker compose $(COMPOSE_FLAGS) run -it --rm $(CONTAINER) /bin/sh

sync-headers:
	@mkdir -p $(DEVENV_DIR)/.include
	docker compose $(COMPOSE_FLAGS) run --rm sdk sh -c "cp -r /sdk/staging_dir/target-*/usr/include/* /sdk/package/luci-sso/devenv/.include/"

compile: $(SENTINEL)

$(SENTINEL): $(wildcard $(PROJECT_ROOT)/mod/*.c) $(wildcard $(PROJECT_ROOT)/mod/*.h) $(PROJECT_ROOT)/mod/CMakeLists.txt
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB)
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/$(CRYPTO_LIB) 2>/dev/null || true
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh compile
	@touch $(SENTINEL)

package:
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/packages
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION) 2>/dev/null || true
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh package
