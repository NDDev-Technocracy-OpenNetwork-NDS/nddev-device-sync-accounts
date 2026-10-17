set shell := ["bash", "-euo", "pipefail", "-c"]

check:
    cargo fmt --check
    cargo nextest run --locked --all-features --jobs 4
    cargo clippy --locked --all-targets --all-features --jobs 4 -- -D warnings
    cargo audit --deny warnings
    cargo deny --locked check licenses sources

generate:
    python3 scripts/generate.py

generated-check:
    python3 scripts/generate.py --check

wasm-check:
    cargo clippy --locked --lib --features browser-bindings --target wasm32-unknown-unknown -- -D warnings

native-store:
    cargo test --locked --test native_store -- --ignored
    cargo test --locked --lib cancellation_after_native_persistence -- --ignored

# NDS_FIXTURE_RECEIPT must name an owned, running local server fixture.
identity-acceptance:
    cargo test --locked --features development-http --test identity_backend -- --ignored
