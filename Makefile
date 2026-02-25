identifier=me.harwell.PawExtensions.OciFnAuth
extensions_dir=$(HOME)/Library/Containers/com.luckymarmot.Paw/Data/Library/Application Support/com.luckymarmot.Paw/Extensions/

.DEFAULT_GOAL := help

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build    Build the extension and copy README and LICENSE into the build output"
	@echo "  clean    Remove the build directory"
	@echo "  install  Clean, build, and install the extension into the Paw extensions directory"
	@echo "  test     Run the test suite via npm"
	@echo "  archive  Build the extension and package it as a zip file in the build directory"

build:
	npm run build
	cp README.md LICENSE ./build/$(identifier)/

clean:
	rm -Rf ./build/

install: clean build
	rm -rf "$(extensions_dir)$(identifier)/"
	mkdir -p "$(extensions_dir)$(identifier)/"
	cp -r ./build/$(identifier)/* "$(extensions_dir)$(identifier)/"

test:
	npm test

archive: build
	cd ./build/; zip -r OciFnAuth.zip "$(identifier)/"
