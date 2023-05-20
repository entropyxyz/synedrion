SHELL = /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := build
.DELETE_ON_ERROR:
.SUFFIXES:

build: pkg

pkg: src
	# Build for both targets
	wasm-pack build -t bundler -d pkg/pkg-bundler
	wasm-pack build -t nodejs -d pkg/pkg-node

	# Clean-up non-essential files
	(cd pkg/pkg-bundler && rm package.json README.md .gitignore)
	(cd pkg/pkg-node && rm package.json README.md .gitignore)

	# Types are duplicated, clean them up to avoid confusion
	mv pkg/pkg-node/synedrion_wasm.d.ts pkg/
	rm pkg/pkg-bundler/synedrion_wasm.d.ts

	# Copy template
	cp package.template.json pkg/package.json
	cp ../LICENSE README.md pkg/


.PHONY: clean

clean:
	rm -rf pkg
