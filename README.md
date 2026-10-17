# nddev-device-sync-accounts

Rust callers may capture `local_use_fence` and call `validate_local_use` around
external awaits. The opaque handle binds this client/cancellation lifetime to
the existing durable authorization generation, protected session binding and
scope. It has no Debug/serialization/FFI and contains no raw token. Checks reuse
the current local expiry/revocation/logout policy; they do not refresh or extend
authority, or make an already sent external request atomically revocable.

Rust identity client for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only.
Email OTP, GitHub and passkey sign-in use protocol v2. Native tokens stay in credential
stores; the client exposes only session metadata and bounded sign-in progress.
Harness profiles and vault recovery are not implemented here. Device enrollment, inventory and revocation use the same native session boundary.

Use the compiler pinned in `rust-toolchain.toml`. `just check` runs formatting, nextest, Clippy and dependency advisory/license gates;
`just native-store` additionally exercises a fresh entry in the actual native
credential service. It requires an unlocked session and never clears a keychain.
`just generate` and `just generated-check` use the immutable `protocol.lock`
source from `NDS_PROTOCOL_SOURCE` (defaults to the adjacent protocol checkout).

HTTPS is required. The opt-in `development-http` feature permits loopback HTTP
in debug builds for isolated local acceptance only; ship without that feature.
HTTP redirects are rejected. Requests and credential operations have 15-second
deadlines. Native and browser credential I/O share one admission policy per endpoint:
one executing call and at most seven waiting callers, with waiting included in the
operation's deadline. A full queue or conflicting identity mutation returns `busy`.
Native OS calls cannot be preempted, so their single admission permit remains
held until the OS call actually returns, including after a caller timeout.
Native read/write/delete outcomes use the same SDK and retain trace context across
the blocking OS worker. A caller wait failure and a later OS completion are distinct;
keys, endpoints, secret values and raw provider errors never enter those events.
Linux uses the native libsecret proxy cache; every read reloads the actual secret.
Provider failure discards that cached proxy without replaying an uncertain write.
The adapter requires an encrypted Secret Service session and rejects ambiguous
or locked records; existing service/username attributes and binary values remain
compatible. Linux builds require libsecret-1 development headers (Debian/Ubuntu:
`libsecret-1-dev`); runtime requires libsecret 0.21 or newer and a Secret Service.

Linux uses Secret Service, Android uses Android Keystore-encrypted preferences
with an application-context JNI initializer, Apple uses Keychain and Windows
uses Credential Manager. Platform declarations are not platform acceptance.
The Flutter bridge must never export the transport `SessionIssued` or
`GithubStart` secret fields. Use `View` only. Never log tokens, OTPs or raw bodies.

The WebAssembly adapter uses the same Rust identity/device rules and signed wire
protocol. It restricts fetches to the application origin, rejects redirects and
keeps the NDS session in a Secure/HttpOnly cookie. Browser credential records use
authenticated encryption under a non-extractable Web Crypto key in IndexedDB;
raw bearer tokens cannot be persisted there. This is browser-profile protection,
not an OS keychain or protection from compromised same-origin script.

After real session and active-device verification, the client can restore a
scoped offline authorization until the original session expiry. Two protected
grant slots and an atomic generation pointer preserve the previous grant across
an interrupted replacement. The metadata pointer contains no credentials.
`View` distinguishes current server verification, cached offline authorization
and a locally completed logout awaiting server revocation. A known local logout
prevents automatic reuse of a retained cookie. Browser logout removes cached
vault keys/grants while preserving device identity and encrypted unsent data.
`authorize_local` is the local secret/replica consumer gate, including changes
made by another process/tab. Offline availability does not assert server freshness.

`just wasm-check` compiles the browser adapter. Actual browser cookie, native
keyring, offline restart and later pipeline acceptance remain separate gates.

`telemetry::Delivery` owns signed event/native OTLP delivery for the desktop and
agent consumers. The SDK owns redaction and record lifetimes; the sender checks
the narrow `/v2/observability/client-policy` export policy, pauses in the background and uses bounded backoff with
at most eight failed sends per batch and 30-minute retention. Delivery's own
credential reads and requests remain local diagnostics, outside the export feeds.
Sign-out/termination closes the feeds; transport acknowledgements are reported
separately for logs and actual spans and do not imply searchable delivery.

The sender does not require global operator status or incident privileges.
Company administrators and ordinary users retain telemetry delivery; denial of
an operator request does not invalidate their personal session. The server must
provide the narrow policy route before deploying this client revision.

Enabled trace receipts accept zero through the submitted span count, with no
duplicates. The SDK counts accepted spans as delivered and the remainder as
dropped. Events still require `accepted + duplicates` to cover the entire batch.
A known full or partial receipt remains with its batch until local settlement;
a failed local acknowledgement retries that settlement without resending HTTP.
The browser SDK preserves the existing sender lease while that owner retries,
without extending payload retention or acquiring another owner's lease. Scope
loss, cancellation and termination stop the sender. A known late receipt can
make one local acknowledgement attempt on its existing owned tail after expiry.
Unknown responses and a crash or cancellation before local commit retain delivery
uncertainty; this does not provide exactly-once export. Native freshness advances
only after a full acknowledgement; browser freshness comes from committed SDK
health, so partial acceptance does not claim a new full-success timestamp.

The ignored `actual_signed_client_delivery_and_incidents` test requires owned
server and observability fixture receipts through `NDS_FIXTURE_RECEIPT` and
`NDS_OBSERVABILITY_FIXTURE_RECEIPT`. It exercises real native credentials, signed
HTTP, PostgreSQL, Vector and searchable OpenObserve spans, incident replay and
resolution, background/resume and absence of recursive export. Fixture credentials
and generated identities remain outside public source.

Owners can list passkey fingerprints/registration times and remove a credential
through the native client. Removal requires a fresh server-verified session and
returns the committed current-session revocation result directly. A subsequent
ordinary refresh removes a revoked cached bearer; vault and device keys persist.
The browser acceptance exercises two actual virtual authenticators, selective
credential/session revocation, idempotent absence, and preservation of OTP login.
Physical authenticator qualification is separate.

Browser telemetry uses the SDK's authenticated-scope IndexedDB spool. RAM ingress
staging runs independently of the common native/browser HTTP sender; a stalled
request cannot block new durable batches. Retry counters survive page restart,
and sender locks are released during backoff or backgrounding while the receipt
is unknown. A known receipt keeps the same sender for local settlement. The delivery view
reports the browser's last payload-write readiness separately from transport
policy and acknowledgements. A readable store does not prove quota recovery.
Scope changes stop the sender before old queued data can acquire another owner.

`screen` is the Rust-only RDS control boundary. It acquires a separate protected
purpose key and endpoint ownership lease, leaving ordinary identity operations
available. The stable key survives logout; local cancellation, revalidation,
logout or client destruction clears the owned RAM key. The opaque owner retains
its exclusive purpose lease while native teardown may still hold a copied key;
the caller drops that owner only after the endpoint and copied material close. `LocalUseFence` guards key acquisition and the seven signed control
calls before and after I/O; capture, media and presentation remain with RDS and
the existing client composition.

Each endpoint instance receives one UUID. Binding retries retain that UUID,
key and original base revision while refreshing the exact HTTP nonce/expiry and
Core V2 endpoint proof. A proof that would exceed current session expiry fails
closed. Create replay preserves original fields and the current state; retained
`Ended` metadata is terminal even when returned with HTTP 201. Create retains
its exact original request bytes; Ready retries retain
the original opaque artifact. Grants stay in bounded Rust control buffers,
outside Flutter, telemetry, URLs and synchronization. The server remains the
canonical authority for participant roles, binding revisions and finite
retention; metadata and Ready do not authorize capture. Lost acknowledgements
or termination before local reconciliation retain delivery uncertainty.

Company transport uses the closed `CompanyRequest` route set and generated
Protocol company DTOs. Signed company requests revalidate the original local
identity lifetime before publishing responses. Administrative denials do not
clear a valid session. `import_invitation` accepts only an exact-instance root
URL with a canonical fragment; it retains one link in Rust memory, refuses an
active account/flow, and selects the existing email OTP workflow. Success or
cancellation clears the link. No token is exposed in `View`. Browser composition
captures and clears the fragment before presentation routing.

Passkey login accepts the Core-validated email selector from presentation and
sends it in the generated request body. It never selects the first/bootstrap
member locally. An omitted selector is resolved only by the server's existing
unambiguous-account rule. Registration rejects a selector and remains bound to
the current authenticated session; selectors are never credential proof or logs.
