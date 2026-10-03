.PHONY: deploy secrets dev test fmt fmt-check clippy clippy-default clippy-dns clippy-proxy lint check-wasm check-default check-dns check-proxy doc deny audit check build build-dns build-proxy build-all release release-snapshot clean

dev:
	@wrangler dev --local-protocol https

deploy:
	@echo Running deploy tool...
	@node ./scripts/deploy.js

secrets:
	@echo Generating secrets tool...
	@node ./scripts/secrets.js

test:
	cargo test --workspace --exclude cfwp

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy: clippy-default clippy-dns clippy-proxy

clippy-default:
	cargo clippy --workspace --target wasm32-unknown-unknown --all-targets -- -D warnings

clippy-dns:
	cargo clippy --workspace --target wasm32-unknown-unknown --all-targets --no-default-features --features dns -- -D warnings

clippy-proxy:
	cargo clippy --workspace --target wasm32-unknown-unknown --all-targets --no-default-features --features proxy -- -D warnings

lint: fmt-check clippy

check-wasm: check-default check-dns check-proxy

check-default:
	cargo check --workspace --target wasm32-unknown-unknown

check-dns:
	cargo check --workspace --target wasm32-unknown-unknown --no-default-features --features dns

check-proxy:
	cargo check --workspace --target wasm32-unknown-unknown --no-default-features --features proxy

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --target wasm32-unknown-unknown --no-deps --all-features

deny:
	cargo deny check

audit:
	cargo audit

check: fmt-check check-wasm clippy test doc deny audit

build:
	node ./scripts/build.js release

build-dns:
	CFWP_FEATURES=dns node ./scripts/build.js release

build-proxy:
	CFWP_FEATURES=proxy node ./scripts/build.js release

build-all:
	CFWP_FEATURES=dns,proxy node ./scripts/build.js release

release:
	node ./scripts/package.js
	goreleaser release --clean --config .goreleaser.yml

release-snapshot:
	node ./scripts/package.js
	goreleaser release --snapshot --clean --config .goreleaser.yml

clean:
	cargo clean
	rm -rf dist/
