//! Rust-only protected endpoint keys and canonical screen control calls.
//! Native RDS owns endpoint/media I/O and grant verification; metadata is not consent.
use crate::{ClientError, IdentityClient, LocalUseFence, State, screen_wire as dto};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nddev_device_sync_application::screen::ScreenTarget;
use nddev_device_sync_domain::{
    DeviceId, UserId,
    devices::{DeviceName, DevicePlatform, MAX_ACTIVE_DEVICES},
    screen::{
        EndpointBinding, MAX_NATIVE_GRANT_BYTES, MAX_VIEW_ID_BYTES, MAX_VIEW_MS, ViewLease,
        ViewPermit, ViewProjection, ViewState, endpoint_signing_bytes,
    },
    sync::MAX_REVISION,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct KeyMaterial {
    seed: Zeroizing<[u8; 32]>,
}

/// One protected purpose key/endpoint instance. No serialized or UI key handle.
/// The caller closes its native endpoint before dropping this owner.
pub struct RdsEndpointKey {
    fence: LocalUseFence,
    device: DeviceId,
    instance: uuid::Uuid,
    base: Mutex<Option<u64>>,
    key: Arc<Mutex<Option<KeyMaterial>>>,
    // Native teardown may still own a copied key. Exclusivity ends only when
    // this opaque owner is dropped after that endpoint has actually closed.
    _lease: crate::store::RdsLease,
}
impl RdsEndpointKey {
    pub fn device(&self) -> &DeviceId {
        &self.device
    }
    pub fn instance_id(&self) -> [u8; 16] {
        *self.instance.as_bytes()
    }
    pub fn public_key(&self) -> Result<[u8; 32], ClientError> {
        self.with_key(|key| Ok(*key.verifying_key().as_bytes()))
    }
    fn with_key<T>(
        &self,
        use_key: impl FnOnce(SigningKey) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        let key = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let material = key.as_ref().ok_or(ClientError::RevalidationRequired)?;
        use_key(SigningKey::from_bytes(&material.seed))
    }
    pub(crate) fn fence(&self) -> &LocalUseFence {
        &self.fence
    }
    pub(crate) fn claim(
        &self,
        origin: &str,
        context: &crate::sync::SigningContext,
        base_revision: u64,
    ) -> Result<Vec<u8>, ClientError> {
        if context.device != self.device || base_revision >= MAX_REVISION {
            return Err(ClientError::InvalidInput);
        }
        let mut base = self.base.lock().unwrap_or_else(|e| e.into_inner());
        if base.is_some_and(|original| original != base_revision) {
            return Err(ClientError::InvalidInput);
        }
        // Keep the original base even when the HTTP acknowledgement is lost.
        *base = Some(base_revision);
        let endpoint = self.public_key()?;
        let transcript = endpoint_signing_bytes(
            origin,
            &self.device,
            &endpoint,
            self.instance.as_bytes(),
            base_revision,
            &context.nonce,
            context.expires_at_ms,
        )
        .map_err(|_| ClientError::InvalidInput)?;
        let proof = self.with_key(|key| Ok(key.sign(&transcript).to_bytes()))?;
        let mut request = dto::ScreenBindRequest {
            endpoint_public_key: URL_SAFE_NO_PAD.encode(endpoint),
            instance_id: self.instance.hyphenated().to_string(),
            base_revision: base_revision as i64,
            nonce: context.nonce.clone(),
            expires_at_ms: context.expires_at_ms as i64,
            signature: URL_SAFE_NO_PAD.encode(proof),
        };
        let body = serde_json::to_vec(&request).map_err(|_| ClientError::InvalidInput);
        request.nonce.zeroize();
        request.signature.zeroize();
        body
    }
}
impl Drop for RdsEndpointKey {
    fn drop(&mut self) {
        self.key.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}
pub(crate) fn close_key(state: &mut State) {
    if let Some(key) = state.rds_key.upgrade() {
        key.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
    state.rds_key = std::sync::Weak::new();
}

/// The exact original create body remains owned across uncertain HTTP responses.
pub struct ScreenCreate {
    request: dto::ScreenViewRequest,
    body: Vec<u8>,
}
impl ScreenCreate {
    pub fn new(request: dto::ScreenViewRequest) -> Result<Self, ClientError> {
        DeviceId::new(request.target_device_id.clone()).map_err(|_| ClientError::InvalidInput)?;
        if request.idempotency_key.is_empty()
            || request.idempotency_key.len() > 256
            || !request
                .idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
            || positive_revision(request.viewer_revision).is_err()
            || positive_revision(request.host_revision).is_err()
            || u32::try_from(request.display).is_err()
            || !(1..=60).contains(&request.max_fps)
            || !(16..=1080).contains(&request.output_height)
            || !(1..=MAX_REVISION as i64).contains(&request.expires_at_ms)
        {
            return Err(ClientError::InvalidInput);
        }
        let body = serde_json::to_vec(&request).map_err(|_| ClientError::InvalidInput)?;
        Ok(Self { request, body })
    }
}

/// Opaque native grant bytes; no Debug, serde, Flutter or arbitrary signer API.
pub struct ScreenArtifact(Zeroizing<Vec<u8>>);
impl ScreenArtifact {
    pub fn new(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_GRANT_BYTES {
            return Err(ClientError::InvalidInput);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn body(&self) -> Result<Vec<u8>, ClientError> {
        let mut request = dto::ScreenReadyRequest {
            native_grant: URL_SAFE_NO_PAD.encode(self.bytes()),
        };
        let result = serde_json::to_vec(&request).map_err(|_| ClientError::InvalidInput);
        request.native_grant.zeroize();
        result
    }
}
pub struct ScreenDelivery {
    pub view: ViewProjection,
    pub artifact: Option<ScreenArtifact>,
}

pub(crate) enum Request<'a> {
    Targets(&'a UserId),
    Binding(&'a DeviceId),
    Bind(&'a RdsEndpointKey, u64),
    Create(&'a ScreenCreate),
    Incoming,
    View(&'a str),
    Ready(&'a ViewProjection, &'a ScreenArtifact),
    End(&'a str),
}
type PreparedRequest = (http::Method, String, Option<Vec<u8>>, u16);

impl Request<'_> {
    pub(crate) fn prepare(
        &self,
        origin: &str,
        context: &crate::sync::SigningContext,
    ) -> Result<PreparedRequest, ClientError> {
        use http::Method;
        Ok(match self {
            Self::Targets(user) => {
                if matches!(user.as_str(), "." | "..") {
                    return Err(ClientError::InvalidInput);
                }
                (
                    Method::GET,
                    format!("/v2/rds/targets/{}", user.as_str()),
                    None,
                    200,
                )
            }
            Self::Binding(target) => {
                if matches!(target.as_str(), "." | "..") {
                    return Err(ClientError::InvalidInput);
                }
                (
                    Method::GET,
                    format!("/v2/rds/bindings/{}", target.as_str()),
                    None,
                    200,
                )
            }
            Self::Bind(key, base) => (
                Method::POST,
                "/v2/rds/bindings".into(),
                Some(key.claim(origin, context, *base)?),
                200,
            ),
            Self::Create(request) => {
                let now = context.now_ms;
                let expires = request.request.expires_at_ms as u64;
                if request.request.target_device_id == context.device.as_str()
                    || expires <= now
                    || expires > now.saturating_add(MAX_VIEW_MS)
                    || expires > context.session_expires_at_ms
                {
                    return Err(ClientError::InvalidInput);
                }
                (
                    Method::POST,
                    "/v2/rds/views".into(),
                    Some(request.body.clone()),
                    201,
                )
            }
            Self::Incoming => (Method::GET, "/v2/rds/views/incoming".into(), None, 200),
            Self::View(id) | Self::End(id) => {
                view_id(id)?;
                if matches!(self, Self::End(_)) {
                    (Method::POST, format!("/v2/rds/views/{id}/end"), None, 204)
                } else {
                    (Method::GET, format!("/v2/rds/views/{id}"), None, 200)
                }
            }
            Self::Ready(view, artifact) => {
                view_id(view.id())?;
                if view.permit().host != context.device {
                    return Err(ClientError::InvalidInput);
                }
                (
                    Method::POST,
                    format!("/v2/rds/views/{}/ready", view.id()),
                    Some(artifact.body()?),
                    200,
                )
            }
        })
    }
}

impl IdentityClient {
    /// Transient discovery only; every view still needs fresh binding authority
    /// and explicit host consent. No personal inventory key reaches this projection.
    pub async fn screen_targets(
        &self,
        fence: &LocalUseFence,
        user: &UserId,
    ) -> Result<Vec<ScreenTarget>, ClientError> {
        let reply = self.screen_request(fence, Request::Targets(user)).await?;
        targets(decode(&reply)?, user)
    }

    /// Persist/reconcile a distinct purpose seed before binding a native endpoint.
    pub async fn rds_endpoint_key(&self) -> Result<RdsEndpointKey, ClientError> {
        let (_permit, cancel) = self.operation().await?;
        let fence = self.local_use_fence().await?;
        let view = self.view();
        let device =
            DeviceId::new(view.current_device_id).map_err(|_| ClientError::RevalidationRequired)?;
        let store = self
            .store
            .rds_store(&view.tenant_id, &view.user_id, device.as_str());
        let lease = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(ClientError::Cancelled),
            result = store.rds_lease() => result?,
        };
        self.validate_local_use(&fence).await?;
        let seed = match store.read().await? {
            Some(seed) => seed,
            None => {
                self.validate_local_use(&fence).await?;
                if cancel.is_cancelled() {
                    return Err(ClientError::Cancelled);
                }
                let mut seed = Zeroizing::new([0; 32]);
                SystemRandom::new()
                    .fill(seed.as_mut())
                    .map_err(|_| ClientError::CredentialStore)?;
                store.write(seed.as_ref()).await?;
                let restored = store.read().await?.ok_or(ClientError::CredentialStore)?;
                if restored.as_slice() != seed.as_ref() {
                    return Err(ClientError::CredentialStore);
                }
                restored
            }
        };
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| ClientError::CredentialStore)?,
        );
        self.validate_local_use(&fence).await?;
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let key = Arc::new(Mutex::new(Some(KeyMaterial { seed })));
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if cancel.is_cancelled() {
                return Err(ClientError::Cancelled);
            }
            state.rds_key = Arc::downgrade(&key);
        }
        Ok(RdsEndpointKey {
            fence,
            device,
            instance: uuid::Uuid::new_v4(),
            base: Mutex::new(None),
            key,
            _lease: lease,
        })
    }

    /// Privileged Rust endpoint composition only. No automatic per-frame I/O.
    pub async fn rds_key_material(
        &self,
        key: &RdsEndpointKey,
    ) -> Result<Zeroizing<[u8; 32]>, ClientError> {
        self.validate_local_use(key.fence()).await?;
        let material = key.key.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Zeroizing::new(
            *material
                .as_ref()
                .ok_or(ClientError::RevalidationRequired)?
                .seed,
        ))
    }

    pub async fn screen_binding(
        &self,
        fence: &LocalUseFence,
        target: &DeviceId,
    ) -> Result<Option<EndpointBinding>, ClientError> {
        let reply = self.screen_request(fence, Request::Binding(target)).await?;
        let response: dto::ScreenBindingResponse = decode(&reply)?;
        response
            .binding
            .map(|row| {
                let binding = binding(row)?;
                if &binding.device != target {
                    return Err(ClientError::InvalidResponse);
                }
                Ok(binding)
            })
            .transpose()
    }
    pub async fn screen_bind(
        &self,
        key: &RdsEndpointKey,
        original_base: u64,
    ) -> Result<EndpointBinding, ClientError> {
        let reply = self
            .screen_request(key.fence(), Request::Bind(key, original_base))
            .await?;
        let result = binding(decode(&reply)?)?;
        if result.device != key.device
            || result.endpoint != key.public_key()?
            || result.instance_id != key.instance_id()
            || original_base.checked_add(1) != Some(result.revision)
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(result)
    }
    pub async fn screen_create(
        &self,
        fence: &LocalUseFence,
        request: &ScreenCreate,
    ) -> Result<ViewProjection, ClientError> {
        let reply = self.screen_request(fence, Request::Create(request)).await?;
        let view = projection(decode(&reply)?)?;
        let permit = view.permit();
        let expected = &request.request;
        if permit.viewer.as_str() != self.view().current_device_id
            || permit.host.as_str() != expected.target_device_id
            || permit.viewer_revision != expected.viewer_revision as u64
            || permit.host_revision != expected.host_revision as u64
            || permit.lease.display() != expected.display as u32
            || permit.lease.max_fps() != expected.max_fps as u32
            || permit.lease.output_height() != expected.output_height as u32
            || permit.lease.expires_at_ms() > expected.expires_at_ms as u64
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(view)
    }
    pub async fn screen_incoming(
        &self,
        fence: &LocalUseFence,
    ) -> Result<Option<ViewProjection>, ClientError> {
        let reply = self.screen_request(fence, Request::Incoming).await?;
        let response: dto::ScreenIncoming = decode(&reply)?;
        response
            .view
            .map(|row| {
                let view = projection(row)?;
                if view.permit().host.as_str() != self.view().current_device_id {
                    return Err(ClientError::InvalidResponse);
                }
                Ok(view)
            })
            .transpose()
    }
    pub async fn screen_view(
        &self,
        fence: &LocalUseFence,
        id: &str,
    ) -> Result<ScreenDelivery, ClientError> {
        let reply = self.screen_request(fence, Request::View(id)).await?;
        let mut response: dto::ScreenViewResponse = decode(&reply)?;
        let ready = matches!(response.view.state, dto::State::Ready);
        let artifact = response
            .native_grant
            .take()
            .map(|value| {
                let value = Zeroizing::new(value);
                if value.len() > 10923 {
                    return Err(ClientError::InvalidResponse);
                }
                let bytes = Zeroizing::new(
                    URL_SAFE_NO_PAD
                        .decode(value.as_bytes())
                        .map_err(|_| ClientError::InvalidResponse)?,
                );
                if bytes.is_empty()
                    || bytes.len() > MAX_NATIVE_GRANT_BYTES
                    || URL_SAFE_NO_PAD.encode(&*bytes) != value.as_str()
                {
                    return Err(ClientError::InvalidResponse);
                }
                Ok(ScreenArtifact(bytes))
            })
            .transpose()?;
        if ready != artifact.is_some() {
            return Err(ClientError::InvalidResponse);
        }
        let view = projection(response.view)?;
        if view.id() != id || view.permit().viewer.as_str() != self.view().current_device_id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(ScreenDelivery { view, artifact })
    }
    pub async fn screen_ready(
        &self,
        fence: &LocalUseFence,
        original: &ViewProjection,
        artifact: &ScreenArtifact,
    ) -> Result<ViewProjection, ClientError> {
        let reply = self
            .screen_request(fence, Request::Ready(original, artifact))
            .await?;
        let row: dto::ScreenView = decode(&reply)?;
        if !matches!(row.state, dto::State::Ready) {
            return Err(ClientError::InvalidResponse);
        }
        let result = projection(row)?;
        if !same_view(original, &result) {
            return Err(ClientError::InvalidResponse);
        }
        Ok(result)
    }
    pub async fn screen_end(&self, fence: &LocalUseFence, id: &str) -> Result<(), ClientError> {
        let reply = self.screen_request(fence, Request::End(id)).await?;
        if !reply.is_empty() {
            return Err(ClientError::InvalidResponse);
        }
        Ok(())
    }
    /// Fresh participant authorization for an already admitted media stream.
    /// This never renews its lease or treats cached metadata as server authority.
    pub async fn screen_revalidate(
        &self,
        fence: &LocalUseFence,
        original: &ViewProjection,
    ) -> Result<bool, ClientError> {
        let device = self.view().current_device_id;
        let current = if original.permit().viewer.as_str() == device {
            Some(self.screen_view(fence, original.id()).await?.view)
        } else if original.permit().host.as_str() == device {
            self.screen_incoming(fence).await?
        } else {
            return Err(ClientError::RevalidationRequired);
        };
        let now = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
            .try_into()
            .map_err(|_| ClientError::RevalidationRequired)?;
        self.validate_local_use(fence).await?;
        current_view(original, current, now)
    }
}

fn current_view(
    original: &ViewProjection,
    current: Option<ViewProjection>,
    now: u64,
) -> Result<bool, ClientError> {
    let Some(mut current) = current else {
        return Ok(false);
    };
    if !same_view(original, &current) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(current.state(now) == ViewState::Ready)
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ClientError> {
    serde_json::from_slice(body).map_err(|_| ClientError::InvalidResponse)
}
fn view_id(id: &str) -> Result<(), ClientError> {
    if !crate::valid_id(id) || id.len() > MAX_VIEW_ID_BYTES || matches!(id, "." | "..") {
        return Err(ClientError::InvalidInput);
    }
    Ok(())
}
fn positive_revision(value: i64) -> Result<u64, ClientError> {
    if !(1..=MAX_REVISION as i64).contains(&value) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(value as u64)
}
fn timestamp(value: i64) -> Result<u64, ClientError> {
    if !(0..=MAX_REVISION as i64).contains(&value) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(value as u64)
}
fn public_key(value: &str) -> Result<[u8; 32], ClientError> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ClientError::InvalidResponse)?
        .try_into()
        .map_err(|_| ClientError::InvalidResponse)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ClientError::InvalidResponse)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value
        || key.is_weak()
        || !key.to_edwards().is_torsion_free()
        || key.to_edwards().compress().to_bytes() != bytes
    {
        return Err(ClientError::InvalidResponse);
    }
    Ok(bytes)
}
fn targets(row: dto::ScreenTargetList, user: &UserId) -> Result<Vec<ScreenTarget>, ClientError> {
    if row.user_id != user.as_str() || row.targets.len() > MAX_ACTIVE_DEVICES {
        return Err(ClientError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    row.targets
        .into_iter()
        .map(|row| {
            if !ids.insert(row.device_id.clone()) {
                return Err(ClientError::InvalidResponse);
            }
            Ok(ScreenTarget {
                device: DeviceId::new(row.device_id).map_err(|_| ClientError::InvalidResponse)?,
                name: DeviceName::new(row.display_name)
                    .map_err(|_| ClientError::InvalidResponse)?,
                platform: match row.platform {
                    dto::Platform::Android => DevicePlatform::Android,
                    dto::Platform::Ios => DevicePlatform::Ios,
                    dto::Platform::Linux => DevicePlatform::Linux,
                    dto::Platform::Macos => DevicePlatform::Macos,
                    dto::Platform::Web => DevicePlatform::Web,
                    dto::Platform::Windows => DevicePlatform::Windows,
                },
                registered: row.registered,
            })
        })
        .collect()
}

fn binding(row: dto::ScreenBinding) -> Result<EndpointBinding, ClientError> {
    let instance =
        uuid::Uuid::parse_str(&row.instance_id).map_err(|_| ClientError::InvalidResponse)?;
    if instance.is_nil() || instance.hyphenated().to_string() != row.instance_id {
        return Err(ClientError::InvalidResponse);
    }
    Ok(EndpointBinding {
        device: DeviceId::new(row.device_id).map_err(|_| ClientError::InvalidResponse)?,
        endpoint: public_key(&row.endpoint_public_key)?,
        revision: positive_revision(row.revision)?,
        instance_id: *instance.as_bytes(),
    })
}
fn projection(row: dto::ScreenView) -> Result<ViewProjection, ClientError> {
    let lease = ViewLease::restore(
        u32::try_from(row.display).map_err(|_| ClientError::InvalidResponse)?,
        u32::try_from(row.max_fps).map_err(|_| ClientError::InvalidResponse)?,
        u32::try_from(row.output_height).map_err(|_| ClientError::InvalidResponse)?,
        timestamp(row.admitted_at_ms)?,
        timestamp(row.expires_at_ms)?,
    )
    .map_err(|_| ClientError::InvalidResponse)?;
    ViewProjection::restore(
        row.view_id,
        ViewPermit {
            viewer: DeviceId::new(row.viewer_device_id)
                .map_err(|_| ClientError::InvalidResponse)?,
            host: DeviceId::new(row.host_device_id).map_err(|_| ClientError::InvalidResponse)?,
            viewer_endpoint: public_key(&row.viewer_endpoint)?,
            host_endpoint: public_key(&row.host_endpoint)?,
            viewer_revision: positive_revision(row.viewer_revision)?,
            host_revision: positive_revision(row.host_revision)?,
            lease,
        },
        match row.state {
            dto::State::Requested => ViewState::Requested,
            dto::State::Ready => ViewState::Ready,
            dto::State::Ended => ViewState::Ended,
        },
    )
    .map_err(|_| ClientError::InvalidResponse)
}
fn same_view(a: &ViewProjection, b: &ViewProjection) -> bool {
    let x = a.permit();
    let y = b.permit();
    a.id() == b.id()
        && x.viewer == y.viewer
        && x.host == y.host
        && x.viewer_endpoint == y.viewer_endpoint
        && x.host_endpoint == y.host_endpoint
        && x.viewer_revision == y.viewer_revision
        && x.host_revision == y.host_revision
        && x.lease.display() == y.lease.display()
        && x.lease.max_fps() == y.lease.max_fps()
        && x.lease.output_height() == y.lease.output_height()
        && x.lease.admitted_at_ms() == y.lease.admitted_at_ms()
        && x.lease.expires_at_ms() == y.lease.expires_at_ms()
}
pub(crate) fn route_template(path: &str) -> Option<&'static str> {
    if path.starts_with("/v2/rds/targets/") {
        Some("/v2/rds/targets/{user_id}")
    } else if path.starts_with("/v2/rds/bindings/") {
        Some("/v2/rds/bindings/{device_id}")
    } else if path.starts_with("/v2/rds/views/") && path != "/v2/rds/views/incoming" {
        Some(if path.ends_with("/ready") {
            "/v2/rds/views/{view_id}/ready"
        } else if path.ends_with("/end") {
            "/v2/rds/views/{view_id}/end"
        } else {
            "/v2/rds/views/{view_id}"
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
