src_path := src
configuration := Debug

docfx_config := doc/docfx.json
docfx_site_dir := doc/_site

formatting_header := \033[1m
formatting_command := \033[1;34m
formatting_desc := \033[0;32m
formatting_error := \033[1;31m
formatting_none := \033[0m

.PHONY: help verify info lint clean build format test unit-test verify-chart doc-serve concordium-tests

.DEFAULT_GOAL := help

## Show help for each of the Makefile recipes.
help:
	@printf "${formatting_header}Available targets:\n"
	@awk -F '## ' '/^## /{desc=$$2}/^[a-zA-Z0-9][a-zA-Z0-9_-]+:/{gsub(/:.*/, "", $$1); printf "  ${formatting_command}%-20s ${formatting_desc}%s${formatting_none}\n", $$1, desc}' $(MAKEFILE_LIST) | sort
	@printf "\n"

## Verify code is ready for commit to branch, runs tests and verifies formatting.
verify: build test lint
	@echo "Code is ready to commit."

## Prints dotnet info
info:
	@echo "Print info and version"
	dotnet --info
	dotnet --version

## Lint the dotnet code
lint:
	@echo "Verifying code formatting..."
	dotnet format $(src_path) --verify-no-changes

## Does a dotnet clean
clean:
	dotnet clean $(src_path)

## Restores all dotnet projects
restore:
	dotnet tool restore --tool-manifest src/.config/dotnet-tools.json
	dotnet restore $(src_path)

## Builds all the code
build: restore
	echo "build for $(configuration)"
	dotnet build $(src_path) --no-restore --configuration $(configuration)

## Formats files using dotnet format
format:
	dotnet format $(src_path)

## Run all tests except Concordium integration
test:
	dotnet test $(src_path)  --filter 'FullyQualifiedName!~ConcordiumIntegrationTests&FullyQualifiedName!~PerformanceTests'

## Run all Unit-tests
unit-test:
	dotnet test $(src_path) --filter 'FullyQualifiedName!~IntegrationTests'

## Builds the local container, creates kind cluster and installs chart, and verifies it works
verify-chart: restore
	@kind version >/dev/null 2>&1 || { echo >&2 "kind not installed! kind is required to use recipe, please install or use devcontainer"; exit 1;}
	@helm version >/dev/null 2>&1 || { echo >&2 "helm not installed! helm is required to use recipe, please install or use devcontainer"; exit 1;}
	charts/project-origin-registry/run_kind_test.sh

## Generate docfx site and serve, navigate to 127.0.0.1:8080
doc-serve: build
	docfx build doc/docfx.json
	docfx serve doc/_site -n 127.0.0.1

## Run Concordium integration tests, requires access to running node and environment variables
concordium-tests:
	dotnet test $(src_path)/ProjectOrigin.VerifiableEventStore.ConcordiumIntegrationTests

## Run performance tests, takes a long time.
verify-performance:
	dotnet test $(src_path)  --filter 'FullyQualifiedName~PerformanceTests'

## Package the nuget package
nuget-pack: build
  ifndef version
	@echo "${formatting_error}Please set the version number. Example: make pack-release version=1.0.0${formatting_none}"
	@exit 2
  endif
  ifndef output_path
	dotnet pack --configuration $(configuration) --no-build -p:Version=$(version) $(src_path)
  else
	dotnet pack --configuration $(configuration) --no-build --output $(output_path) -p:Version=$(version) $(src_path)
  endif
