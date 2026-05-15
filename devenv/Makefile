.ONESHELL:
.SHELLFLAGS = -ec

DEVENV_DIR   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT := $(abspath $(DEVENV_DIR)/..)

GREEN  := \033[1;32m
BLUE   := \033[1;34m
YELLOW := \033[1;33m
RED    := \033[1;31m
RESET  := \033[0m

export UID            := $(shell id -u)
export GID            := $(shell id -g)
export PKI_CURVE      := prime256v1
export NODE_VERSION   := 25
export ALPINE_VERSION := 3.23
export SDK_VERSION    := 24.10.5
export SDK_ARCH       := $(or $(SDK_ARCH),$(shell $(DEVENV_DIR)/scripts/resolve-arch.sh --host))
export ROOTFS_ARCH    := $(shell $(DEVENV_DIR)/scripts/resolve-arch.sh $(SDK_ARCH))
export CRYPTO_LIB     ?= mbedtls
export PKG_DEPENDS    := $(shell grep 'PKG_DEPENDS:=' $(PROJECT_ROOT)/Makefile | sed 's/PKG_DEPENDS:=//' | tr '+' ' ' | tr ' ' '\n' | sort -u | tr '\n' ' ')
export DOMAIN         := luci-sso.test
export FQDN_IDP       := idp.$(DOMAIN)
export FQDN_LUCI      := luci.$(DOMAIN)
export FQDN_BROWSER   := browser.$(DOMAIN)
export PORT_IDP       := 5556
export PORT_LUCI      := 8443
export DOCKER_SUITE   ?= local
export DOCKER_NAMESPACE := ghcr.io/m00qek

SAFE_SDK_VERSION    := $(subst .,-,$(SDK_VERSION))
COMPOSE_FLAGS        = -p $(SDK_ARCH)-$(SAFE_SDK_VERSION) -f $(DEVENV_DIR)/docker-compose.yaml -f $(DEVENV_DIR)/docker-compose.$(DOCKER_SUITE).yaml
INFRA_COMPOSE_FLAGS  = -p luci-sso-infra -f $(DEVENV_DIR)/docker-compose.infra.yaml -f $(DEVENV_DIR)/docker-compose.infra.$(DOCKER_SUITE).yaml

SENTINEL := $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/.built

.PHONY: build-images up down ps shell infra-up infra-down test fuzz e2e watch-tests lint pull

infra-up:
	@echo -e " $(GREEN)🚀$(RESET) Starting infrastructure..."
	docker compose $(INFRA_COMPOSE_FLAGS) up -d --wait --remove-orphans
	@echo -e " $(GREEN)✨$(RESET) Done!"

infra-down:
	@echo -e " $(YELLOW)🛑$(RESET) Stopping infrastructure..."
	docker compose $(INFRA_COMPOSE_FLAGS) down --remove-orphans

up:
	docker compose $(INFRA_COMPOSE_FLAGS) up -d --wait --remove-orphans
	@echo -e " $(GREEN)🚀$(RESET) Starting '$(DOCKER_SUITE)' environment..."
	docker compose $(COMPOSE_FLAGS) up -d --wait --remove-orphans openwrt
	@echo -e " $(GREEN)✨$(RESET) Done!"

down:
	@echo -e " $(YELLOW)🛑$(RESET) Stopping '$(DOCKER_SUITE)' environment..."
	docker compose $(COMPOSE_FLAGS) down --remove-orphans
	docker compose $(INFRA_COMPOSE_FLAGS) down --remove-orphans

ps:
	@docker compose $(COMPOSE_FLAGS) ps

pull:
	@docker compose $(INFRA_COMPOSE_FLAGS) pull
	@docker compose $(COMPOSE_FLAGS) pull

build-images:
	@echo -e " $(BLUE)🔨$(RESET) Building images..."
	docker compose $(INFRA_COMPOSE_FLAGS) build --pull=false
	docker compose $(COMPOSE_FLAGS) build --pull=false

CONTAINER ?= openwrt

shell:
	@docker compose $(COMPOSE_FLAGS) ps -q 2>/dev/null | grep -q . \
	  || { echo -e " $(RED)⛔$(RESET) Not running. Run: make up"; exit 1; }
	@echo -e " $(BLUE)🐚$(RESET) Entering $(CONTAINER)..."
	docker compose $(COMPOSE_FLAGS) exec $(CONTAINER) /bin/sh

test: DOCKER_SUITE = ci
test:
	@docker compose $(INFRA_COMPOSE_FLAGS) ps -q idp 2>/dev/null | grep -q . \
	  || { echo -e " $(RED)⛔$(RESET) Infrastructure not running. Run: make infra-up DOCKER_SUITE=ci"; exit 1; }
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" INFRA_COMPOSE_FLAGS="$(INFRA_COMPOSE_FLAGS)" \
	  $(DEVENV_DIR)/scripts/test.sh unit --modules "$(MODULES)" --filter "$(FILTER)"

e2e: DOCKER_SUITE = ci
e2e:
	@docker compose $(INFRA_COMPOSE_FLAGS) ps -q idp 2>/dev/null | grep -q . \
	  || { echo -e " $(RED)⛔$(RESET) Infrastructure not running. Run: make infra-up DOCKER_SUITE=ci"; exit 1; }
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" INFRA_COMPOSE_FLAGS="$(INFRA_COMPOSE_FLAGS)" \
	  $(DEVENV_DIR)/scripts/test.sh e2e --modules "$(MODULES)" --filter "$(FILTER)"

watch-tests: DOCKER_SUITE = ci
watch-tests:
	@docker compose $(INFRA_COMPOSE_FLAGS) ps -q idp 2>/dev/null | grep -q . \
	  || { echo -e " $(RED)⛔$(RESET) Infrastructure not running. Run: make infra-up DOCKER_SUITE=ci"; exit 1; }
	@COMPOSE_FLAGS="$(COMPOSE_FLAGS)" INFRA_COMPOSE_FLAGS="$(INFRA_COMPOSE_FLAGS)" \
	  $(DEVENV_DIR)/scripts/test.sh watch --modules "$(MODULES)" --filter "$(FILTER)"

TIME ?= 60
DETECT_LEAKS ?= 0

fuzz: DOCKER_SUITE = ci
fuzz:
	@echo -e " $(BLUE)🧪$(RESET) Running native fuzz tests for $(CRYPTO_LIB) ($(TIME)s)..."
	docker compose $(COMPOSE_FLAGS) pull fuzzer || true
	docker compose $(COMPOSE_FLAGS) run --rm -e ASAN_OPTIONS="detect_leaks=$(DETECT_LEAKS)" fuzzer bash -c " \
		mkdir -p bin/fuzz && cd bin/fuzz && \
		cmake -DENABLE_FUZZING=ON ../../src && \
		make -j$$(nproc) && \
		./fuzz_$(CRYPTO_LIB) -max_total_time=$(TIME) -rss_limit_mb=2048"

lint:
	@echo -e " $(BLUE)🔍$(RESET) Running documentation lint checks..."
	@bash $(DEVENV_DIR)/scripts/check-error-codes.sh
	@bash $(DEVENV_DIR)/scripts/check-request-limits.sh
	@bash $(DEVENV_DIR)/scripts/check-cookie-names.sh
	@echo -e " $(GREEN)✅$(RESET) All lint checks passed."

compile: $(SENTINEL)

$(SENTINEL): $(wildcard $(PROJECT_ROOT)/src/*.c) $(wildcard $(PROJECT_ROOT)/src/*.h) $(PROJECT_ROOT)/src/CMakeLists.txt
	@echo -e " $(BLUE)🔨$(RESET) Building native components for $(SDK_ARCH)..."
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh compile
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION) 2>/dev/null || true
	@touch $(SENTINEL)

package:
	@echo -e " $(BLUE)📦$(RESET) Building IPK package for $(SDK_ARCH)..."
	@mkdir -p $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION)/packages
	@chmod -R a+rwx $(PROJECT_ROOT)/bin/lib/$(SDK_ARCH)/$(SDK_VERSION) 2>/dev/null || true
	docker compose $(COMPOSE_FLAGS) run --rm sdk /bin/bash /usr/local/bin/build.sh package

sync-headers:
	@echo -e " $(BLUE)🔄$(RESET) Syncing headers for LSP..."
	@mkdir -p $(DEVENV_DIR)/.include
	docker compose $(COMPOSE_FLAGS) run --rm sdk sh -c "cp -r /sdk/staging_dir/target-*/usr/include/* /sdk/package/luci-sso/devenv/.include/"

VAR ?= ""
print-env:
	@echo "$${$(VAR)}"
