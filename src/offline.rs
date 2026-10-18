//! Protected last-known authorization. The domain owns scope/expiry; platform
//! adapters own secrets and the atomic generation pointer. Two fixed slots keep
//! the prior grant intact if a process dies while publishing its replacement.
use crate::{
    ClientError, IdentityClient, SessionCredential, View,
    store::{Fence, FenceMode},
    view::DeviceView,
    wire,
};
use nddev_device_sync_domain::{
    DeviceId, TenantId, UserId,
    identity::{CachedDeviceAuthorization, Owner},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
mod renewal;

/// Opaque point-in-time local-use observation, never a new authorization grant.
/// Rust callers recheck it around external awaits; no token/key or serializable
/// handle is exposed. A sent external request cannot be revoked retroactively.
pub struct LocalUseFence {
    client: std::sync::Weak<()>,
    durable: Fence,
    scope: CachedDeviceAuthorization,
    session_binding: Option<String>,
}

impl LocalUseFence {
    pub(crate) fn expires_at_ms(&self) -> u64 {
        self.scope.expires_at_ms
    }
}

/// Opaque local cancellation observation, usable before device enrollment.
/// It contains no authorization, key or durable grant and is not serializable.
pub struct LocalUseLifetime {
    client: std::sync::Weak<()>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    schema_version: u8,
    generation: String,
    authorization: CachedDeviceAuthorization,
    session: wire::Session,
    device: DeviceView,
    credential_fingerprint: Option<String>,
    server_version: String,
}

fn now_ms() -> Result<u64, ClientError> {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .map_err(|_| ClientError::RevalidationRequired)
}

impl SessionCredential {
    fn fingerprint(&self) -> Option<String> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::Bearer(token) => {
                use sha2::{Digest, Sha256};
                Some(base16ct::lower::encode_string(&Sha256::digest(
                    token.as_bytes(),
                )))
            }
            #[cfg(target_arch = "wasm32")]
            Self::BrowserCookie => None,
        }
    }
}

impl Cached {
    fn validate(
        &self,
        origin: &str,
        fence: &Fence,
        credential: &SessionCredential,
    ) -> Result<(), ClientError> {
        self.validate_at(origin, fence, credential, now_ms()?)
    }

    fn validate_at(
        &self,
        origin: &str,
        fence: &Fence,
        credential: &SessionCredential,
        now: u64,
    ) -> Result<(), ClientError> {
        let owner = Owner {
            user_id: UserId::new(&self.session.user_id)
                .map_err(|_| ClientError::CredentialStore)?,
            tenant_id: TenantId::new(&self.session.tenant_id)
                .map_err(|_| ClientError::CredentialStore)?,
        };
        let device =
            DeviceId::new(&self.device.device_id).map_err(|_| ClientError::CredentialStore)?;
        let expires = OffsetDateTime::parse(&self.session.expires_at, &Rfc3339)
            .map_err(|_| ClientError::CredentialStore)?;
        if !(1..=2).contains(&self.schema_version)
            || (self.schema_version == 1 && self.authorization.authorization_id.is_some())
            || fence.mode != FenceMode::Ready
            || self.generation != fence.generation
            || !self.device.is_current
            || self.device.revoked
            || self.server_version.len() > 128
            || self.credential_fingerprint != credential.fingerprint()
            || expires.unix_timestamp_nanos() / 1_000_000
                < i128::from(self.authorization.expires_at_ms)
        {
            return Err(ClientError::RevalidationRequired);
        }
        self.authorization
            .authorize_offline(origin, &owner, &device, now)
            .map_err(|_| ClientError::RevalidationRequired)
    }
}

impl IdentityClient {
    pub(crate) fn authority_online(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .authority_online
    }

    /// An account inventory response alone cannot reauthorize device traffic.
    pub fn require_online_verification(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.authority_online = false;
        state.next_authority_maintenance = None;
        state.next_authority_verification = None;
    }

    async fn read_cached_slot(&self, slot: u8) -> Result<Option<Cached>, ClientError> {
        let Some(secret) = self.store.offline_store(slot).read().await? else {
            return Ok(None);
        };
        if secret.len() > 8192 {
            return Err(ClientError::CredentialStore);
        }
        serde_json::from_slice(&secret)
            .map(Some)
            .map_err(|_| ClientError::CredentialStore)
    }

    async fn ready_fence(&self) -> Result<Option<Fence>, ClientError> {
        let Some(fence) = self.store.authorization_fence(None).await? else {
            return Ok(None);
        };
        if fence.mode != FenceMode::Ready {
            if matches!(fence.mode, FenceMode::SignedOut | FenceMode::PendingLogout) {
                self.clear_session();
                self.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .view
                    .logout_pending = fence.mode == FenceMode::PendingLogout;
            } else {
                self.require_revalidation();
            }
            return Ok(None);
        }
        Ok(Some(fence))
    }

    async fn cached_with_fence(
        &self,
        credential: &SessionCredential,
    ) -> Result<Option<(Cached, Fence)>, ClientError> {
        let Some(fence) = self.ready_fence().await? else {
            return Ok(None);
        };
        self.cached_at_fence(credential, fence).await
    }

    async fn cached_at_fence(
        &self,
        credential: &SessionCredential,
        fence: Fence,
    ) -> Result<Option<(Cached, Fence)>, ClientError> {
        let Some(cached) = self.read_cached_slot(fence.slot).await? else {
            return Ok(None);
        };
        cached.validate(&self.origin(), &fence, credential)?;
        // A sign-out/revocation or slot publication may race a protected-store
        // read. Do not publish a decision from a superseded metadata generation.
        if self.store.authorization_fence(None).await?.as_ref() != Some(&fence) {
            return Err(ClientError::Busy);
        }
        Ok(Some((cached, fence)))
    }

    pub(crate) async fn restore_offline(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Option<View>, ClientError> {
        // A fresh/signed-out installation has no offline capability. Do not
        // read its native secret backend or mask the original server failure.
        let Some(fence) = self.ready_fence().await? else {
            return Ok(None);
        };
        let Some(credential) = self.stored_session_credential().await? else {
            return Ok(None);
        };
        let Some((cached, _)) = self.cached_at_fence(&credential, fence).await? else {
            return Ok(None);
        };
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let deadline = crate::validate_session(&cached.session)?;
        let remaining = cached
            .authorization
            .expires_at_ms
            .checked_sub(now_ms()?)
            .ok_or(ClientError::RevalidationRequired)?;
        let deadline =
            deadline.min(crate::Instant::now() + std::time::Duration::from_millis(remaining));
        let checked = i64::try_from(cached.authorization.verified_at_ms / 1000)
            .map_err(|_| ClientError::CredentialStore)?;
        let _completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let anchor = (
            cached.generation.clone(),
            cached.authorization.verified_at_ms,
        );
        if let Some((generation, _)) = &state.cached_authority
            && generation != &anchor.0
        {
            state.local_use_generation = std::sync::Arc::default();
            crate::screen::close_key(&mut state);
        }
        state.session_deadline = Some(if state.cached_authority.as_ref() == Some(&anchor) {
            state
                .session_deadline
                .map_or(deadline, |previous| previous.min(deadline))
        } else {
            deadline
        });
        state.cached_authority = Some(anchor);
        state.authority_online = false;
        state.view.authenticated = true;
        state.view.session_verified = false;
        state.view.offline_authorized = true;
        state.view.offline_cache_ready = true;
        state.view.credential_store_ready = true;
        state.view.credential_revalidation_required = false;
        state.view.session_checked_at = checked;
        state.view.devices_checked_at = checked;
        state.view.current_device_id = cached.device.device_id.clone();
        state.view.devices = vec![cached.device];
        state.view.server_version = cached.server_version;
        state.view.user_id = cached.session.user_id;
        state.view.tenant_id = cached.session.tenant_id;
        state.view.expires_at = cached.session.expires_at;
        state.view.auth_method = match cached.session.auth_method {
            wire::AuthMethod::EmailOtp => "email_otp",
            wire::AuthMethod::Github => "github",
            wire::AuthMethod::Passkey => "passkey",
        }
        .into();
        drop(state);
        tracing::event!(target:"nds_accounts",tracing::Level::INFO, {event.name="identity.offline.restored",outcome="ok"});
        Ok(Some(self.view()))
    }

    pub(crate) async fn invalidate_offline(&self, mode: FenceMode) -> Result<(), ClientError> {
        crate::screen::close_key(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
        let old = self.store.authorization_fence(None).await?;
        self.store
            .authorization_fence(Some((old, Fence::new(mode)?)))
            .await?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.view.offline_authorized = false;
        state.view.offline_cache_ready = false;
        state.authority_online = false;
        state.next_authority_maintenance = None;
        Ok(())
    }

    /// Local key/replica consumers must consult the durable shared decision,
    /// including a sign-out completed by another process or browser tab.
    pub async fn authorize_local(&self) -> Result<(), ClientError> {
        self.authorized_local_with_fence().await.map(|_| ())
    }

    /// Capture the existing protected scope/session and durable generation for
    /// this client. Cancellation invalidates the observation without sign-out.
    pub async fn local_use_fence(&self) -> Result<LocalUseFence, ClientError> {
        let lifetime = self.local_use_lifetime();
        self.local_use_fence_from(&lifetime).await
    }

    /// Capture this client's existing lifetime without I/O or authorization.
    /// Call before the first await when enrollment must precede a full fence.
    pub fn local_use_lifetime(&self) -> LocalUseLifetime {
        LocalUseLifetime {
            client: self.local_use_generation(),
        }
    }

    /// Check only the captured local lifetime, without protected I/O or a grant.
    /// Cleanup must hold its publication/cancellation guard while checking and
    /// detaching owners, so an old failure cannot remove a replacement's tasks.
    pub fn check_captured_local_use_lifetime(
        &self,
        lifetime: &LocalUseLifetime,
    ) -> Result<(), ClientError> {
        self.check_local_use_generation(&lifetime.client)
    }

    /// Acquire the existing protected scope under the original local lifetime.
    /// Cancellation cannot be replaced by a fresh observation after an await.
    pub async fn local_use_fence_from(
        &self,
        lifetime: &LocalUseLifetime,
    ) -> Result<LocalUseFence, ClientError> {
        self.check_captured_local_use_lifetime(lifetime)?;
        let (cached, durable) = self.authorized_local_with_fence().await?;
        self.check_captured_local_use_lifetime(lifetime)?;
        Ok(LocalUseFence {
            client: lifetime.client.clone(),
            durable,
            scope: cached.authorization,
            session_binding: cached.credential_fingerprint,
        })
    }

    /// Synchronous point-in-time check of this client's captured lifetime only.
    /// Does no protected I/O and grants no authorization. Callers must perform
    /// validate_local_use first, then check inside a brief publication critical
    /// section serialized with their cancellation entry point. That entry point
    /// must hold the same publication lock while rotating the existing generation.
    pub fn check_local_use_lifetime(&self, fence: &LocalUseFence) -> Result<(), ClientError> {
        self.check_local_use_generation(&fence.client)
    }

    /// Recheck current protected authorization, not just owner IDs. Same-owner
    /// sign-out/relogin or another process/tab generation change rejects a late
    /// result. This method does not refresh or extend the underlying grant.
    pub async fn validate_local_use(&self, fence: &LocalUseFence) -> Result<(), ClientError> {
        self.check_local_use_generation(&fence.client)?;
        let (cached, durable) = self.authorized_local_with_fence().await?;
        let scope = cached.authorization;
        if durable.generation != fence.durable.generation
            || durable.mode != FenceMode::Ready
            || cached.credential_fingerprint != fence.session_binding
            || !scope.continues(&fence.scope, now_ms()?)
        {
            return Err(ClientError::RevalidationRequired);
        }
        self.check_local_use_generation(&fence.client)
    }

    fn local_use_generation(&self) -> std::sync::Weak<()> {
        std::sync::Arc::downgrade(
            &self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .local_use_generation,
        )
    }
    fn check_local_use_generation(
        &self,
        expected: &std::sync::Weak<()>,
    ) -> Result<(), ClientError> {
        if std::sync::Weak::ptr_eq(expected, &self.local_use_generation()) {
            Ok(())
        } else {
            Err(ClientError::RevalidationRequired)
        }
    }

    async fn authorized_local_with_fence(&self) -> Result<(Cached, Fence), ClientError> {
        let credential = self.session_credential().await?;
        let (cached, fence) = self
            .cached_with_fence(&credential)
            .await?
            .ok_or(ClientError::RevalidationRequired)?;
        let replaced = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let replaced = state
                .cached_authority
                .as_ref()
                .is_some_and(|(generation, _)| generation != &fence.generation);
            if replaced {
                state.local_use_generation = std::sync::Arc::default();
            }
            replaced
        };
        if replaced {
            self.require_revalidation();
            return Err(ClientError::RevalidationRequired);
        }
        let view = self.view();
        if !view.authenticated
            || view.credential_revalidation_required
            || view.user_id != cached.session.user_id
            || view.tenant_id != cached.session.tenant_id
            || view.current_device_id != cached.device.device_id
            || !view
                .devices
                .iter()
                .any(|device| device.is_current && !device.revoked)
        {
            self.require_revalidation();
            return Err(ClientError::RevalidationRequired);
        }
        Ok((cached, fence))
    }

    pub(crate) async fn finish_pending_logout(
        &self,
        cancel: &CancellationToken,
    ) -> Result<bool, ClientError> {
        let fence = self.store.authorization_fence(None).await?;
        if !fence
            .as_ref()
            .is_some_and(|f| matches!(f.mode, FenceMode::PendingLogout | FenceMode::SignedOut))
        {
            return Ok(false);
        }
        self.clear_session();
        if fence.is_some_and(|f| f.mode == FenceMode::SignedOut) {
            // The remote logout is already acknowledged. Preserve an explicit
            // new sign-in flow and never emit another DELETE/generation change.
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.view.logout_pending = false;
            state.view.credential_store_ready = true;
            return Ok(true);
        }
        self.clear_flow();
        #[cfg(target_arch = "wasm32")]
        self.store.clear_browser_access().await?;
        #[cfg(not(target_arch = "wasm32"))]
        for slot in 0..2 {
            self.store.offline_store(slot).delete().await?;
        }
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .logout_pending = true;
        if let Some(credential) = self.stored_session_credential().await? {
            match self
                .request::<()>(
                    http::Method::DELETE,
                    "/v2/session",
                    None,
                    Some(&credential),
                    "en",
                    cancel,
                )
                .await
            {
                Ok((http::StatusCode::NO_CONTENT, _)) => {}
                Err(ClientError::Server(code)) if code == "authentication_failed" => {}
                Err(error) => return Err(error),
                _ => return Err(ClientError::InvalidResponse),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.store.delete().await?;
        // Keep the local signed-out decision until an explicit successful new
        // sign-in. A delayed ambient cookie must not silently restore access.
        self.invalidate_offline(FenceMode::SignedOut).await?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .logout_pending = false;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .credential_store_ready = true;
        tracing::event!(target:"nds_accounts",tracing::Level::INFO,{event.name="identity.remote_logout.completed",outcome="ok"});
        Ok(true)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod local_use_tests {
    use super::*;

    #[test]
    fn legacy_protected_grant_keeps_its_expiry_and_accepts_only_clock_observations() {
        let credential =
            SessionCredential::Bearer(Zeroizing::new("generated-invalid-test-value".into()));
        let fence = Fence::new(FenceMode::Ready).unwrap();
        let verified = 1_900_000_000_000;
        let expiry = verified + 8 * 60 * 60 * 1000;
        let mut value = serde_json::json!({
            "schema_version":1,"generation":fence.generation,
            "authorization":{"origin":"https://legacy.example","user_id":"owner","tenant_id":"tenant",
                "device_id":"device","verified_at_ms":verified,"expires_at_ms":expiry},
            "session":{"user_id":"owner","tenant_id":"tenant","auth_method":"email_otp",
                "expires_at":OffsetDateTime::from_unix_timestamp_nanos(i128::from(expiry)*1_000_000).unwrap().format(&Rfc3339).unwrap()},
            "device":{"device_id":"device","display_name":"Owned test","platform":"linux",
                "revoked":false,"is_current":true,"created_at":"2030-01-01T00:00:00Z"},
            "credential_fingerprint":credential.fingerprint(),"server_version":"test"
        });
        let mut cached: Cached = serde_json::from_value(value.clone()).unwrap();
        assert!(cached.authorization.authorization_id.is_none());
        assert!(
            cached
                .validate_at("https://legacy.example", &fence, &credential, expiry - 1)
                .is_ok()
        );
        assert_eq!(
            cached.validate_at("https://legacy.example", &fence, &credential, expiry),
            Err(ClientError::RevalidationRequired)
        );
        cached
            .authorization
            .observe_clock(verified + 60_000)
            .unwrap();
        assert_eq!(cached.authorization.expires_at_ms, expiry);
        assert_eq!(cached.authorization.verified_at_ms, verified);
        assert!(
            cached
                .validate_at(
                    "https://legacy.example",
                    &fence,
                    &credential,
                    verified + 59_999
                )
                .is_err()
        );
        assert!(
            cached
                .validate_at(
                    "https://other.example",
                    &fence,
                    &credential,
                    verified + 60_000
                )
                .is_err()
        );
        value["authorization"]["authorization_id"] = serde_json::json!(vec![1; 32]);
        let wrong: Cached = serde_json::from_value(value).unwrap();
        assert!(
            wrong
                .validate_at("https://legacy.example", &fence, &credential, verified)
                .is_err()
        );
    }

    #[tokio::test]
    async fn pre_enrollment_lifetime_cannot_cross_client_or_survive_cancel() {
        let client = IdentityClient::new("https://captured-life.example").unwrap();
        let other = IdentityClient::new("https://captured-life.example").unwrap();
        let lifetime = client.local_use_lifetime();
        assert!(client.check_captured_local_use_lifetime(&lifetime).is_ok());
        assert!(client.view().current_device_id.is_empty());
        assert!(!client.view().credential_revalidation_required);
        assert!(matches!(
            other.local_use_fence_from(&lifetime).await,
            Err(ClientError::RevalidationRequired)
        ));
        assert_eq!(
            other.check_captured_local_use_lifetime(&lifetime),
            Err(ClientError::RevalidationRequired)
        );
        assert!(!other.view().credential_revalidation_required);
        client.cancel();
        *client.cancellation.lock().unwrap() = CancellationToken::new();
        assert_eq!(
            client.check_captured_local_use_lifetime(&lifetime),
            Err(ClientError::RevalidationRequired)
        );
        assert!(matches!(
            client.local_use_fence_from(&lifetime).await,
            Err(ClientError::RevalidationRequired)
        ));
        assert!(!client.view().credential_revalidation_required);
        let renewed = client.local_use_lifetime();
        assert!(client.check_local_use_generation(&renewed.client).is_ok());
        client.cancel_sign_in();
        assert!(matches!(
            client.local_use_fence_from(&renewed).await,
            Err(ClientError::RevalidationRequired)
        ));
    }

    #[test]
    fn new_sign_in_invalidates_local_lifetime_but_same_session_refresh_preserves_it() {
        let client = IdentityClient::new("https://example.invalid").unwrap();
        let session = wire::Session {
            user_id: "owner".into(),
            tenant_id: "tenant".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
            auth_method: wire::AuthMethod::EmailOtp,
        };
        let deadline = crate::Instant::now() + std::time::Duration::from_secs(60);
        let initial = client.local_use_lifetime();
        client.set_session(session.clone(), deadline, false);
        assert!(client.check_captured_local_use_lifetime(&initial).is_err());
        let current = client.local_use_lifetime();
        client.set_session(session.clone(), deadline, true);
        assert!(client.check_captured_local_use_lifetime(&current).is_ok());
        client.set_session(session, deadline, false);
        assert!(client.check_captured_local_use_lifetime(&current).is_err());
    }

    #[test]
    fn local_use_is_client_bound_and_cancel_survives_request_token_rotation() {
        let client = IdentityClient::new("https://local-use.example").unwrap();
        let other = IdentityClient::new("https://local-use.example").unwrap();
        let generation = client.local_use_generation();
        assert!(client.check_local_use_generation(&generation).is_ok());
        assert!(other.check_local_use_generation(&generation).is_err());
        *client.cancellation.lock().unwrap() = CancellationToken::new();
        assert!(client.check_local_use_generation(&generation).is_ok());
        client.cancel();
        *client.cancellation.lock().unwrap() = CancellationToken::new();
        assert!(client.check_local_use_generation(&generation).is_err());
        let renewed = client.local_use_generation();
        client.cancel_sign_in();
        assert!(client.check_local_use_generation(&renewed).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod acceptance {
    use super::*;
    use futures::FutureExt;
    use nddev_device_sync_telemetry::{Config, ExportFeed, client_traces::ClientTraces};
    use opentelemetry_proto::tonic::{
        collector::trace::v1::ExportTraceServiceRequest, common::v1::any_value, trace::v1::Span,
    };
    use prost::Message;
    use serde_json::Value;
    use std::{path::PathBuf, time::Duration};
    use tracing::instrument::WithSubscriber;

    fn process_spans(feed: &ExportFeed) -> Vec<Span> {
        let mut spans = Vec::new();
        while let Some(batch) = feed.take_batch() {
            let decoded = ExportTraceServiceRequest::decode(batch.bytes()).unwrap();
            spans.extend(
                decoded
                    .resource_spans
                    .into_iter()
                    .flat_map(|resource| resource.scope_spans)
                    .flat_map(|scope| scope.spans)
                    .filter(|span| {
                        span.attributes.iter().any(|field| {
                            field.key == "scope"
                                && field.value.as_ref().and_then(|v| v.value.as_ref())
                                    == Some(&any_value::Value::StringValue("process".into()))
                        })
                    }),
            );
            batch.acknowledge();
        }
        spans
    }

    fn assert_recovered_operation(feed: &ExportFeed) {
        let spans = process_spans(feed);
        assert_eq!(spans.len(), 1);
        let status = spans[0].status.as_ref().unwrap();
        assert_eq!(
            status.code, 0,
            "handled network failure is not terminal failure"
        );
        assert!(status.message.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires an owned controllable PostgreSQL/Mailpit fixture, private state root and real unlocked keyring"]
    async fn actual_offline_recreation_preserves_authorization_and_sign_out() {
        let receipt = PathBuf::from(std::env::var("NDS_FIXTURE_RECEIPT").unwrap());
        let data: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        let endpoint = data["base_url"].as_str().unwrap();
        let mailbox = data["mailpit_url"].as_str().unwrap();
        let owner = data["owner_email"].as_str().unwrap();
        assert!(
            (endpoint.starts_with("http://127.0.0.1:")
                || endpoint.starts_with("http://localhost:"))
                && mailbox.starts_with("http://127.0.0.1:")
        );
        assert!(owner.ends_with(".invalid"));
        let control = receipt.with_extension("control.json");
        assert_eq!(
            data["control_file"].as_str().unwrap(),
            control.to_str().unwrap()
        );
        assert!(!control.exists());
        let client = IdentityClient::new(endpoint).unwrap();
        assert!(client.store.read().await.unwrap().is_none());
        let config = Config {
            service: "nddev-device-sync-client".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-desktop".into(),
            commit: "unknown".into(),
            channel: "alpha".into(),
            standards: "unreleased".into(),
            environment: "test".into(),
            target_prefixes: vec!["nds_accounts".into()],
            default_module: "accounts".into(),
            debug: None,
        };
        let traces = ClientTraces::new(&config).unwrap();
        let feed = traces.subscribe().unwrap();
        let (subscriber, _) =
            nddev_device_sync_telemetry::subscriber(config, std::io::sink(), traces.tracer())
                .unwrap();
        let mut owned_device = None;
        let result = std::panic::AssertUnwindSafe(async {
            client.refresh().await.unwrap();
            client.request_email(owner.into(), "en").await.unwrap();
            let http = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            let code = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let messages: Value = http
                        .get(format!("{mailbox}/api/v1/messages"))
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    if let Some(id) = messages["messages"]
                        .as_array()
                        .and_then(|m| m.first())
                        .and_then(|m| m["ID"].as_str())
                    {
                        let message: Value = http
                            .get(format!("{mailbox}/api/v1/message/{id}"))
                            .send()
                            .await
                            .unwrap()
                            .json()
                            .await
                            .unwrap();
                        if let Some((_, code)) =
                            message["Text"].as_str().unwrap().split_once("code: ")
                        {
                            break code.chars().take(8).collect::<String>();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
            client.verify_email(code).await.unwrap();
            let device_store = client.device_store().unwrap();
            assert!(device_store.read().await.unwrap().is_none());
            owned_device = Some(device_store);
            let enrolled = client
                .prepare_device("Owned offline acceptance".into())
                .await
                .unwrap();
            assert!(
                enrolled.offline_cache_ready
                    && enrolled.session_verified
                    && !enrolled.offline_authorized
            );
            let refreshed = client.refresh().await.unwrap();
            assert_eq!(refreshed.current_device_id, enrolled.current_device_id);
            assert_eq!(refreshed.devices_checked_at, enrolled.devices_checked_at);
            client.authorize_local().await.unwrap();
            let captured = client.local_use_fence().await.unwrap();
            let before = client
                .cached_with_fence(&client.session_credential().await.unwrap())
                .await
                .unwrap()
                .unwrap();
            {
                let mut state = client.state.lock().unwrap();
                state.next_authority_maintenance = None;
            }
            client.maintain_authorization().await.unwrap();
            let renewed = client
                .cached_with_fence(&client.session_credential().await.unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(before.1.generation, renewed.1.generation);
            assert_ne!(before.1.slot, renewed.1.slot);
            assert_eq!(
                before.0.authorization.authorization_id,
                renewed.0.authorization.authorization_id
            );
            assert!(
                renewed.0.authorization.verified_at_ms >= before.0.authorization.verified_at_ms
            );
            assert!(renewed.0.authorization.expires_at_ms >= before.0.authorization.expires_at_ms);
            client.validate_local_use(&captured).await.unwrap();
            {
                let (_permit, cancel) = client.operation().await.unwrap();
                client.checkpoint_authorization(&cancel).await.unwrap();
            }
            let checkpoint = client
                .cached_with_fence(&client.session_credential().await.unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                checkpoint.0.authorization.verified_at_ms,
                renewed.0.authorization.verified_at_ms
            );
            assert_eq!(
                checkpoint.0.authorization.expires_at_ms,
                renewed.0.authorization.expires_at_ms
            );
            assert_eq!(checkpoint.1.generation, renewed.1.generation);
            assert_ne!(checkpoint.1.slot, renewed.1.slot);
            client.validate_local_use(&captured).await.unwrap();
            let key = client
                .device_store()
                .unwrap()
                .read()
                .await
                .unwrap()
                .unwrap();
            set_mode(&receipt, &control, "offline").await;
            let recreated = IdentityClient::new(endpoint).unwrap();
            process_spans(&feed);
            let offline = recreated.refresh().await.unwrap();
            assert_recovered_operation(&feed);
            assert!(
                offline.authenticated && offline.offline_authorized && !offline.session_verified
            );
            assert_eq!(offline.current_device_id, enrolled.current_device_id);
            assert_eq!(offline.expires_at, renewed.0.session.expires_at);
            assert!(offline.session_checked_at <= OffsetDateTime::now_utc().unix_timestamp());
            recreated.authorize_local().await.unwrap();
            assert!(matches!(
                recreated
                    .sync_request(crate::SyncRequest::Page { after: 0, limit: 1 })
                    .await,
                Err(ClientError::OnlineVerificationRequired)
            ));
            let deadline = recreated.state.lock().unwrap().session_deadline.unwrap();
            recreated
                .restore_offline(&CancellationToken::new())
                .await
                .unwrap()
                .unwrap();
            assert!(recreated.state.lock().unwrap().session_deadline.unwrap() <= deadline);
            recreated.maintain_authorization().await.unwrap();
            let offline_cache = recreated
                .cached_with_fence(&recreated.session_credential().await.unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                offline_cache.0.authorization.verified_at_ms,
                checkpoint.0.authorization.verified_at_ms
            );
            assert_eq!(
                offline_cache.0.authorization.expires_at_ms,
                checkpoint.0.authorization.expires_at_ms
            );
            let offline_use = recreated.local_use_fence().await.unwrap();
            set_mode(&receipt, &control, "online").await;
            recreated.require_online_verification();
            let connected = recreated.maintain_authorization().await.unwrap();
            assert!(
                connected.session_verified
                    && connected.offline_cache_ready
                    && !connected.offline_authorized
            );
            recreated.validate_local_use(&offline_use).await.unwrap();
            assert_eq!(
                recreated
                    .sync_request(crate::SyncRequest::Page { after: 0, limit: 1 })
                    .await
                    .unwrap()
                    .status,
                200
            );
            set_mode(&receipt, &control, "offline").await;
            process_spans(&feed);
            let signed_out = recreated.logout().await.unwrap();
            assert_recovered_operation(&feed);
            assert!(!signed_out.authenticated && signed_out.logout_pending);
            assert!(
                client.authorize_local().await.is_err(),
                "another client retained local access after logout"
            );
            assert!(matches!(
                client
                    .sync_request(crate::SyncRequest::Page { after: 0, limit: 1 })
                    .await,
                Err(ClientError::RevalidationRequired)
            ));
            let closed = IdentityClient::new(endpoint).unwrap();
            assert!(closed.refresh().await.is_err());
            assert!(!closed.view().authenticated);
            set_mode(&receipt, &control, "online").await;
            let after = closed.refresh().await.unwrap();
            assert!(!after.authenticated && !after.logout_pending && after.credential_store_ready);
            assert!(closed.store.read().await.unwrap().is_none());
            let acknowledged = closed.store.authorization_fence(None).await.unwrap();
            closed.refresh().await.unwrap();
            assert!(
                closed.store.authorization_fence(None).await.unwrap() == acknowledged,
                "an acknowledged logout must not create another durable decision"
            );
            let device_store = client
                .store
                .device_store(&enrolled.tenant_id, &enrolled.user_id);
            assert_eq!(
                device_store.read().await.unwrap().unwrap().as_slice(),
                key.as_slice()
            );
        })
        .catch_unwind()
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;
        // The fixture and every native entry are explicitly owned. Cleanup is
        // also attempted after assertion failure, without touching real scopes.
        client.store.delete().await.unwrap();
        if let Some(store) = owned_device {
            store.delete().await.unwrap();
        }
        set_mode(&receipt, &control, "online").await;
        for slot in 0..2 {
            client.store.offline_store(slot).delete().await.unwrap();
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    async fn set_mode(receipt: &std::path::Path, control: &std::path::Path, mode: &str) {
        std::fs::write(
            control,
            serde_json::to_vec(&serde_json::json!({"mode":mode})).unwrap(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let state = std::fs::read(receipt)
                    .ok()
                    .and_then(|data| serde_json::from_slice::<Value>(&data).ok());
                if !control.exists()
                    && state.as_ref().is_some_and(|s| {
                        s["status"]
                            == if mode == "online" {
                                "running"
                            } else {
                                "offline"
                            }
                    })
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
}
