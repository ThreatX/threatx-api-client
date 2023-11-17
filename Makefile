# 
base_dir ?= $(shell pwd)

.PHONY: clean
clean: ## Remove temporary files and build artifacts
	@echo "🧹 Cleaning up temporary files and build artifacts ..."
	test -d dist && rm -rf dist || true
	test -d build && rm -rf build || true

.PHONY: install
install: ## Install Dependencies
	@echo "🚀 Installing dependencies ..."
	@poetry shell
	@poetry install

.PHONY: devinstall
devinstall:  install ## Install ALL dependencies
	@echo "🚀 Installing OPTIONAL dependencies ..."
	@poetry install --with docs --with dev --with release

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.DEFAULT_GOAL := help
