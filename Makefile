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
verify: test lint
	@echo "Code is ready to commit."

## Prints dotnet info
info:
	@echo "Print info and version"
	dotnet --info
	dotnet --version

## Lint the dotnet code
lint:
	@echo "Verifying code formatting..."
	dotnet format --verify-no-changes

## Does a dotnet clean
clean:
	dotnet clean

## Restores all dotnet projects
restore:
	dotnet restore

## Builds all the code
build: restore
	dotnet build --no-restore

## Formats files using dotnet format
format:
	dotnet format

## Run all tests
test: build
	dotnet test --no-build

## Tests run with the sonarcloud analyser
sonarcloud-test:
	dotnet test --no-build
