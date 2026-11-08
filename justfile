set shell := ["bash", "-euo", "pipefail", "-c"]

setup:
    bun install --frozen-lockfile --ignore-scripts

# Source-only checks. Dependencies must already be prepared by setup.
check: browser-check
    cargo fmt --check
    cargo deny --locked check licenses sources
    cargo shear --locked --deny-warnings

# Execution host or runner only.
test:
    cargo nextest run --locked --all-features --jobs 4 --profile ci
    cargo clippy --locked --all-targets --all-features --jobs 4 -- -D warnings
    cargo test --locked --doc --jobs 4
    bun run test

# Full acceptance needs owned native-store and backend fixtures.
verify: check test wasm-check generated-check native-store identity-acceptance
    cargo build --locked --release --jobs 4
    cargo audit --deny warnings

generate:
    python3 scripts/generate.py

generated-check:
    python3 scripts/generate.py --check

browser-check:
    bun run check
    bun run check:generated

wasm-check:
    cargo clippy --locked --lib --features browser-bindings --target wasm32-unknown-unknown -- -D warnings

native-store:
    cargo test --locked --test native_store -- --ignored
    cargo test --locked --lib cancellation_after_native_persistence -- --ignored

# NDS_FIXTURE_RECEIPT must name an owned, running local server fixture.
identity-acceptance:
    cargo test --locked --features development-http --test identity_backend -- --ignored
