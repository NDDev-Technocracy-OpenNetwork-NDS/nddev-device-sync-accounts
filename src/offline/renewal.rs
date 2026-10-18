//! Signed server receipts and bounded maintenance under the existing identity
//! writer lease. Clock checkpoints cannot issue or extend an authorization.
use super::*;
use crate::{Instant, SyncRequest};
use nddev_device_sync_domain::identity::SESSION_LIFETIME_MS;
use std::time::Duration;

const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(60);
const VERIFICATION_INTERVAL: Duration = Duration::from_secs(300);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

fn timestamp(value: &str) -> Result<u64, ClientError> {
    (OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ClientError::InvalidResponse)?
        .unix_timestamp_nanos()
        / 1_000_000)
        .try_into()
        .map_err(|_| ClientError::InvalidResponse)
}

impl IdentityClient {
    /// Called by the existing reconciliation owner; no task or timer is spawned.
    /// Busy defers without cancelling another identity or module operation.
    pub async fn maintain_authorization(&self) -> Result<View, ClientError> {
        let view = self.view();
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !view.flow.is_empty()
                || (!view.authenticated && state.cached_authority.is_none() && !view.logout_pending)
                || state
                    .next_authority_maintenance
                    .is_some_and(|due| due > Instant::now())
            {
                return Ok(view);
            }
        }
        self.observe(
            "identity.authority.maintain",
            self.maintain_authorization_inner(),
        )
        .await
    }

    async fn maintain_authorization_inner(&self) -> Result<View, ClientError> {
        let (_permit, cancel) = match self.operation().await {
            Ok(value) => value,
            Err(ClientError::Busy) => return Ok(self.view()),
            Err(error) => return Err(error),
        };
        if self.finish_pending_logout(&cancel).await? {
            return Ok(self.view());
        }
        let verify = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            !state.authority_online
                || state
                    .next_authority_verification
                    .is_none_or(|due| due <= Instant::now())
        };
        let result = async {
            let view = self.view();
            if verify {
                if !view.authenticated
                    || view.credential_revalidation_required
                    || view.current_device_id.is_empty()
                {
                    self.refresh_online(&cancel).await?;
                }
                let current = self.view();
                if !current.authenticated || current.current_device_id.is_empty() {
                    return Ok(());
                }
                self.renew_authorization_inner(&cancel).await
            } else {
                self.checkpoint_authorization(&cancel).await
            }
        }
        .await;
        let result = async {
            if result.as_ref().is_err_and(crate::online_unavailable) {
                // Preserve a finite previously issued grant. No network failure can
                // change verified_at/expiry or manufacture online device authority.
                if self.restore_offline(&cancel).await?.is_some() {
                    self.checkpoint_authorization(&cancel).await
                } else {
                    result
                }
            } else {
                result
            }
        }
        .await;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.next_authority_maintenance = Some(
            Instant::now()
                + if state.authority_online {
                    CHECKPOINT_INTERVAL
                } else {
                    RETRY_INTERVAL
                },
        );
        drop(state);
        result?;
        Ok(self.view())
    }

    pub(crate) async fn renew_authorization_inner(
        &self,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        self.require_online_verification();
        let requested = now_ms()?;
        let reply = self
            .signed_request_inner(SyncRequest::SessionRenewal, cancel)
            .await?;
        if reply.status != 200 {
            return Err(ClientError::InvalidResponse);
        }
        let receipt: wire::SessionRenewal = crate::decode(&reply.body)?;
        let received = now_ms()?;
        let verified = timestamp(&receipt.verified_at)?;
        let expires = timestamp(&receipt.session.expires_at)?;
        let view = self.view();
        if receipt.session.user_id != view.user_id
            || receipt.session.tenant_id != view.tenant_id
            || verified < requested.saturating_sub(30_000)
            || verified > received.saturating_add(30_000)
            || received < requested
            || verified.checked_add(SESSION_LIFETIME_MS) != Some(expires)
        {
            return Err(ClientError::InvalidResponse);
        }
        let deadline = crate::validate_session(&receipt.session)?;
        let device = view
            .devices
            .iter()
            .find(|device| device.is_current && !device.revoked)
            .cloned()
            .ok_or(ClientError::RevalidationRequired)?;
        let credential = self.session_credential().await?;
        let old = self.store.authorization_fence(None).await?;
        if old
            .as_ref()
            .is_some_and(|f| matches!(f.mode, FenceMode::SignedOut | FenceMode::PendingLogout))
        {
            return Err(ClientError::RevalidationRequired);
        }
        let authorization = CachedDeviceAuthorization {
            origin: self.origin(),
            user_id: UserId::new(&receipt.session.user_id)
                .map_err(|_| ClientError::InvalidResponse)?,
            tenant_id: TenantId::new(&receipt.session.tenant_id)
                .map_err(|_| ClientError::InvalidResponse)?,
            device_id: DeviceId::new(&device.device_id)
                .map_err(|_| ClientError::InvalidResponse)?,
            verified_at_ms: received,
            expires_at_ms: expires.min(
                received
                    .checked_add(SESSION_LIFETIME_MS)
                    .ok_or(ClientError::InvalidResponse)?,
            ),
            authorization_id: Some(crate::devices::canonical_bytes(&receipt.authorization_id)?),
            clock_observed_at_ms: received,
        };
        let previous = match &old {
            Some(fence) if fence.mode == FenceMode::Ready => {
                self.read_cached_slot(fence.slot).await?
            }
            _ => None,
        };
        let same = old
            .as_ref()
            .zip(previous.as_ref())
            .is_some_and(|(fence, cached)| {
                cached
                    .validate_at(
                        &self.origin(),
                        fence,
                        &credential,
                        cached
                            .authorization
                            .verified_at_ms
                            .max(cached.authorization.clock_observed_at_ms),
                    )
                    .is_ok()
                    && cached.authorization.authorization_id == authorization.authorization_id
                    && cached.authorization.origin == authorization.origin
                    && cached.authorization.user_id == authorization.user_id
                    && cached.authorization.tenant_id == authorization.tenant_id
                    && cached.authorization.device_id == authorization.device_id
            });
        if same
            && previous.as_ref().is_some_and(|cached| {
                received
                    < cached
                        .authorization
                        .clock_observed_at_ms
                        .max(cached.authorization.verified_at_ms)
            })
        {
            return Err(ClientError::RevalidationRequired);
        }
        let mut next = if same {
            old.clone().unwrap()
        } else {
            Fence::new(FenceMode::Ready)?
        };
        next.slot = old.as_ref().map_or(0, |f| 1 - f.slot);
        let cached = Cached {
            schema_version: 2,
            generation: next.generation.clone(),
            authorization,
            session: receipt.session.clone(),
            device,
            credential_fingerprint: credential.fingerprint(),
            server_version: view.server_version,
        };
        cached.validate(&self.origin(), &next, &credential)?;
        if let Err(error) = self.publish_cached(old, next, &cached, cancel).await {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .offline_cache_ready = false;
            tracing::event!(target:"nds_accounts",tracing::Level::WARN,
                {event.name="identity.offline.persistence_failed",error.type=error.code(),outcome="error"});
            return Err(error);
        }
        let _completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        self.set_session(receipt.session, deadline, true);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .cached_authority
            .as_ref()
            .is_some_and(|(generation, _)| generation != &cached.generation)
        {
            state.local_use_generation = std::sync::Arc::default();
            crate::screen::close_key(&mut state);
        }
        state.cached_authority = Some((cached.generation, cached.authorization.verified_at_ms));
        state.authority_online = true;
        state.view.offline_cache_ready = true;
        state.next_authority_verification = Some(Instant::now() + VERIFICATION_INTERVAL);
        state.next_authority_maintenance = Some(Instant::now() + CHECKPOINT_INTERVAL);
        drop(state);
        tracing::event!(target:"nds_accounts",tracing::Level::INFO,
            {event.name="identity.authority.renewed",outcome="ok"});
        Ok(())
    }

    async fn publish_cached(
        &self,
        old: Option<Fence>,
        next: Fence,
        cached: &Cached,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(cached).map_err(|_| ClientError::CredentialStore)?);
        if bytes.len() > 8192 {
            return Err(ClientError::CredentialStore);
        }
        self.store.offline_store(next.slot).write(&bytes).await?;
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        self.store.authorization_fence(Some((old, next))).await?;
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        Ok(())
    }

    pub(super) async fn checkpoint_authorization(
        &self,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let credential = self.session_credential().await?;
        let Some((mut cached, old)) = self.cached_with_fence(&credential).await? else {
            return Err(ClientError::RevalidationRequired);
        };
        cached
            .authorization
            .observe_clock(now_ms()?)
            .map_err(|_| ClientError::RevalidationRequired)?;
        let mut next = old.clone();
        next.slot = 1 - old.slot;
        self.publish_cached(Some(old), next, &cached, cancel)
            .await?;
        tracing::event!(target:"nds_accounts",tracing::Level::DEBUG,
            {event.name="identity.authority.clock_observed",outcome="ok"});
        Ok(())
    }
}
