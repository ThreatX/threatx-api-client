# 
base_dir ?= $(shell git rev-parse --show-toplevel)
docs_dir ?= $(base_dir)/docs
config ?= $(base_dir)/mkdocs.yml
mkdocs_site_dir ?= $(base_dir)/site
mkdocs_opts ?= --config-file $(config) 

.PHONY: clean
clean: ## Remove temporary files and build artifacts
	@echo "🧹 Cleaning up temporary files and build artifacts ..."
	@test -d site && rm -rf site || true

.PHONY: docs
docs:  ## Build the documentation site
	@echo "📚 Building documentation site ..."
	@cd $(base_dir)
	@poetry run mkdocs build $(mkdocs_opts)

.PHONY: serve
listen_port=8000
serve: ## Serve the documentation site
	@echo "🚀 Serving documentation site ..."
	@poetry run mkdocs serve $(mkdocs_opts)
	@open  http://localhost:$(listen_port)

.PHONY: deploy
deploy: ## Deploy the docs to github pages
	@cd $(base_dir)
	@poetry run mkdocs gh-deploy $(mkdocs_opts)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.DEFAULT_GOAL := help
