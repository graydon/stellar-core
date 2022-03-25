.PHONY: build install

build:
	# TODO: Remove --noAssert once we get assert working.
	asc \
		-o test_invoke_contract.wasm \
		-O \
		--disable bulk-memory \
		--runtime stub \
		test_invoke_contract.ts

install:
	npm install -g assemblyscript
