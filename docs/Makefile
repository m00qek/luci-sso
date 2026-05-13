# --- 1. CONFIGURATION ---
.ONESHELL:
.SHELLFLAGS = -ec

# Directory Resolution
DOCS_DIR     := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT := $(abspath $(DOCS_DIR)/..)

# ANSI Color Codes
GREEN := \033[1;32m
BLUE  := \033[1;34m
YELLOW:= \033[1;33m
RED   := \033[1;31m
RESET := \033[0m

# Docker Image
MKDOCS_IMAGE := squidfunk/mkdocs-material:latest

# --- 2. PUBLIC INTERFACE ---
.PHONY: build serve dev clean help

help:
	@echo -e "$(BLUE)LuCI SSO Documentation Toolkit$(RESET)"
	@echo -e "Usage:"
	@echo -e "  make build  - Generate the static site in $(PROJECT_ROOT)/site/"
	@echo -e "  make serve  - Run a live-reloading dev server on http://localhost:8000"
	@echo -e "  make clean  - Remove the generated site directory"

build:
	@echo -e " $(BLUE)🔨$(RESET) Building static documentation..."
	docker run --rm -v $(PROJECT_ROOT):/docs $(MKDOCS_IMAGE) build

serve: dev
dev:
	@echo -e " $(GREEN)🚀$(RESET) Starting documentation server on $(BLUE)http://localhost:8000$(RESET)..."
	@echo -e " $(YELLOW)ℹ️$(RESET)  Press Ctrl+C to stop."
	docker run --rm -it -p 8000:8000 -v $(PROJECT_ROOT):/docs $(MKDOCS_IMAGE)

clean:
	@echo -e " $(YELLOW)🧹$(RESET) Cleaning up generated documentation..."
	rm -rf $(PROJECT_ROOT)/site
