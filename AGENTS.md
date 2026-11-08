# NDS accounts working contract

Own the Rust NDS identity client and native credential adapters. Domain and application
rules remain in core; protocol schemas own wire DTOs. Generate consumers from the pinned
protocol source, never edit generated files.

The browser uses the same Rust client with explicit WebAssembly I/O. Session credentials
stay in Secure/HttpOnly cookies; encrypted credential entries use a non-extractable
browser wrapping key. Offline authorization has two protected slots and one atomic
metadata pointer; that pointer contains no token or key. Preserve scope, original
expiry, cross-process/tab admission and pending logout.

Read README.md, module.yaml and contracts.lock. Public code is AGPL-3.0-only and
generic: no real addresses, credentials, deployment topology or runtime evidence. Keep
session and exchange tokens private to Rust/native stores; no plaintext fallback,
metadata database or Flutter field may contain them. Harness accounts and vaults are
separate.

Preserve live keychains and unrelated dirty work. Tests own only fresh ephemeral
entries. Use bounded requests, cancellation, typed redacted events and errors. Run just
check and real native-store/backend acceptance before claiming support. No deployment,
releases, credential rotation or backup/recovery is implicit.
