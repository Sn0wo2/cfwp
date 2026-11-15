JS_RUNTIME ?= bun

.PHONY: build build-dev clean check-template

check-template:
	node scripts/check-template-sync.js

build:
	worker-build --release --out-dir build .
	$(JS_RUNTIME) scripts/package.js

build-dev:
	worker-build --dev --out-dir build .
	$(JS_RUNTIME) scripts/package.js

clean:
	cargo clean
	rm -rf build dist
