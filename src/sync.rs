use crate::{ClientError, IdentityClient, WireRequest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use http::Method;
use nddev_device_sync_http_signatures as signatures;
use ring::rand::{SecureRandom, SystemRandom};

pub(crate) struct SigningContext {
    pub device: nddev_device_sync_domain::DeviceId,
    pub nonce: String,
    pub created: u64,
    pub now_ms: u64,
    pub expires_at_ms: u64,
    pub session_expires_at_ms: u64,
}

/// A compiled-in route set, never an arbitrary URL or authenticated HTTP proxy.
pub enum SyncRequest {
    Company(crate::company::CompanyRequest),
    Append(Vec<u8>),
    Page {
        after: u64,
        limit: u16,
    },
    /// Explicit lifecycle3 routes; callers retain the original append bytes.
    CapabilitiesV3,
    AppendV3(Vec<u8>),
    HistoryV3 {
        after: u64,
        limit: u16,
    },
    BaseV3 {
        base: u64,
        after_member: u64,
        limit: u16,
    },
    VaultKey(Vec<u8>),
    Telemetry(Vec<u8>),
    NativeTraces(Vec<u8>),
    /// Export policy for any active client; no global operator data.
    TelemetryPolicy,
    ObservabilityStatus,
    Incidents {
        after: String,
    },
    IncidentAction {
        id: String,
        silence: bool,
        body: Vec<u8>,
    },
}
pub struct SyncReply {
    pub status: u16,
    pub body: Vec<u8>,
}
impl SyncRequest {
    fn is_v3(&self) -> bool {
        matches!(
            self,
            Self::CapabilitiesV3 | Self::AppendV3(_) | Self::HistoryV3 { .. } | Self::BaseV3 { .. }
        )
    }
    fn prepare(self) -> Result<(Method, String, Option<Vec<u8>>), ClientError> {
        match self {
            Self::Company(request) => request.prepare(),
            SyncRequest::Telemetry(body) => {
                if body.is_empty() || body.len() > 65_536 {
                    return Err(ClientError::InvalidInput);
                }
                Ok((Method::POST, "/v2/observability/events".into(), Some(body)))
            }
            SyncRequest::NativeTraces(body) => {
                if body.is_empty() || body.len() > 65_536 {
                    return Err(ClientError::InvalidInput);
                }
                Ok((Method::POST, "/v2/observability/traces".into(), Some(body)))
            }
            SyncRequest::TelemetryPolicy => {
                Ok((Method::GET, "/v2/observability/client-policy".into(), None))
            }
            SyncRequest::ObservabilityStatus => {
                Ok((Method::GET, "/v2/observability/status".into(), None))
            }
            SyncRequest::Incidents { after } => {
                if after.len() > 128 || !after.is_empty() && !crate::valid_id(&after) {
                    return Err(ClientError::InvalidInput);
                }
                Ok((
                    Method::GET,
                    format!("/v2/observability/incidents?after={after}"),
                    None,
                ))
            }
            SyncRequest::IncidentAction { id, silence, body } => {
                if !crate::valid_id(&id) || body.len() > 1024 {
                    return Err(ClientError::InvalidInput);
                }
                let action = if silence { "silence" } else { "acknowledge" };
                Ok((
                    Method::POST,
                    format!("/v2/observability/incidents/{id}/{action}"),
                    Some(body),
                ))
            }
            SyncRequest::VaultKey(body) => {
                if body.len() > 1024 {
                    return Err(ClientError::InvalidInput);
                }
                Ok((Method::POST, "/v2/vault/key".into(), Some(body)))
            }
            SyncRequest::Append(body) => {
                if body.len() > nddev_device_sync_domain::sync::MAX_OPERATION_BYTES {
                    return Err(ClientError::InvalidInput);
                }
                Ok((Method::POST, "/v2/sync/operations".into(), Some(body)))
            }
            SyncRequest::CapabilitiesV3 => Ok((Method::GET, "/v3/sync".into(), None)),
            SyncRequest::AppendV3(body) => {
                if body.is_empty()
                    || body.len() > nddev_device_sync_domain::sync::MAX_OPERATION_BYTES
                {
                    return Err(ClientError::InvalidInput);
                }
                Ok((Method::POST, "/v3/sync/operations".into(), Some(body)))
            }
            SyncRequest::HistoryV3 { after, limit } => {
                if after > nddev_device_sync_domain::sync::MAX_REVISION
                    || !(1..=nddev_device_sync_domain::sync::MAX_PAGE_ITEMS as u16).contains(&limit)
                {
                    return Err(ClientError::InvalidInput);
                }
                Ok((
                    Method::GET,
                    format!("/v3/sync/history?after_seq={after}&limit={limit}"),
                    None,
                ))
            }
            SyncRequest::BaseV3 {
                base,
                after_member,
                limit,
            } => {
                if base > nddev_device_sync_domain::sync::MAX_REVISION
                    || after_member > nddev_device_sync_domain::sync::MAX_REVISION
                    || !(1..=nddev_device_sync_domain::sync::MAX_PAGE_ITEMS as u16).contains(&limit)
                {
                    return Err(ClientError::InvalidInput);
                }
                Ok((
                    Method::GET,
                    format!(
                        "/v3/sync/base?base_seq={base}&after_member_seq={after_member}&limit={limit}"
                    ),
                    None,
                ))
            }
            SyncRequest::Page { after, limit } => {
                if after > nddev_device_sync_domain::sync::MAX_REVISION
                    || !(1..=100).contains(&limit)
                {
                    return Err(ClientError::InvalidInput);
                }
                Ok((
                    Method::GET,
                    format!("/v2/sync/operations?after_seq={after}&limit={limit}"),
                    None,
                ))
            }
        }
    }
}

/// An expired retry/cursor is an Unknown outcome, never permission to replace
/// an operation ID, reconstruct its body or delete pending work.
pub enum SyncExpiry {
    V3(crate::sync3_wire::SyncExpired),
    /// The deployed v2 error remains unchanged and carries no new floor/header.
    V2CursorExpired,
}
impl SyncReply {
    pub fn expiry(&self) -> Result<Option<SyncExpiry>, ClientError> {
        if self.status != 410 {
            return Ok(None);
        }
        if let Ok(expired) = decode_expired_v3(&self.body) {
            return Ok(Some(SyncExpiry::V3(expired)));
        }
        decode_expired_v2(&self.body)?;
        Ok(Some(SyncExpiry::V2CursorExpired))
    }
}
pub(crate) fn decode_expired_v3(
    bytes: &[u8],
) -> Result<crate::sync3_wire::SyncExpired, ClientError> {
    use nddev_device_sync_domain::sync::history::HistoryVersion;
    if bytes.len() > crate::MAX_BODY {
        return Err(ClientError::InvalidResponse);
    }
    let value: crate::sync3_wire::SyncExpired =
        serde_json::from_slice(bytes).map_err(|_| ClientError::InvalidResponse)?;
    let floor = u64::try_from(value.floor_seq).map_err(|_| ClientError::InvalidResponse)?;
    let head = u64::try_from(value.head_seq).map_err(|_| ClientError::InvalidResponse)?;
    if value.schema_version != 3 {
        return Err(ClientError::InvalidResponse);
    }
    HistoryVersion {
        floor,
        head,
        base: floor,
    }
    .validate()
    .map_err(|_| ClientError::InvalidResponse)?;
    Ok(value)
}
pub(crate) fn decode_expired_v2(bytes: &[u8]) -> Result<(), ClientError> {
    if bytes.len() > crate::MAX_BODY {
        return Err(ClientError::InvalidResponse);
    }
    let value: crate::sync_wire::Error =
        serde_json::from_slice(bytes).map_err(|_| ClientError::InvalidResponse)?;
    if matches!(value.error, crate::sync_wire::ErrorEnum::CursorExpired) {
        Ok(())
    } else {
        Err(ClientError::InvalidResponse)
    }
}

pub(crate) fn validate_v3_reply_size(
    path: &str,
    status: http::StatusCode,
    bytes: usize,
) -> Result<(), ClientError> {
    use nddev_device_sync_domain::sync::{MAX_PAGE_BYTES, MAX_RESULT_BYTES};
    let route = path.split('?').next().unwrap_or_default();
    let maximum = match (route, status) {
        ("/v3/sync/history" | "/v3/sync/base", http::StatusCode::OK) => MAX_PAGE_BYTES,
        ("/v3/sync/operations", http::StatusCode::CREATED | http::StatusCode::CONFLICT) => {
            MAX_RESULT_BYTES
        }
        _ => crate::MAX_BODY,
    };
    if bytes > maximum {
        Err(ClientError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;

struct Key {
    key: ed25519_dalek::SigningKey,
    id: String,
}
impl signatures::SigningKey for Key {
    fn key_id(&self) -> String {
        self.id.clone()
    }
    fn alg(&self) -> signatures::AlgorithmName {
        signatures::AlgorithmName::Ed25519
    }
    fn sign(&self, data: &[u8]) -> signatures::HttpSigResult<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
}
impl IdentityClient {
    pub(crate) async fn screen_request(
        &self,
        fence: &crate::LocalUseFence,
        request: crate::screen::Request<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientError> {
        let (_permit, cancel) = self.operation().await?;
        self.validate_local_use(fence).await?;
        let view = self.view();
        let current = view
            .devices
            .iter()
            .find(|device| device.is_current && !device.revoked)
            .ok_or(ClientError::RevalidationRequired)?;
        let key = Key {
            key: crate::devices::read_key(&self.device_store()?)
                .await?
                .ok_or(ClientError::RevalidationRequired)?,
            id: current.device_id.clone(),
        };
        let token = self.session_credential().await?;
        self.validate_local_use(fence).await?;
        let mut nonce = [0; 24];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ClientError::CredentialStore)?;
        let wall_now = time::OffsetDateTime::now_utc();
        let now_ms = u64::try_from(wall_now.unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| ClientError::InvalidInput)?;
        let created: u64 = wall_now
            .unix_timestamp()
            .try_into()
            .map_err(|_| ClientError::InvalidInput)?;
        let expires_at_ms = created
            .checked_add(60)
            .and_then(|v| v.checked_mul(1000))
            .ok_or(ClientError::InvalidInput)?;
        if matches!(request, crate::screen::Request::Bind(..))
            && expires_at_ms > fence.expires_at_ms()
        {
            return Err(ClientError::RevalidationRequired);
        }
        let context = SigningContext {
            device: nddev_device_sync_domain::DeviceId::new(current.device_id.clone())
                .map_err(|_| ClientError::InvalidResponse)?,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            created,
            now_ms,
            expires_at_ms,
            session_expires_at_ms: fence.expires_at_ms(),
        };
        let (method, path, body, expected) =
            request.prepare(&self.endpoint.origin().ascii_serialization(), &context)?;
        let body = body.map(zeroize::Zeroizing::new);
        let target = self
            .endpoint
            .join(&path)
            .map_err(|_| ClientError::InvalidEndpoint)?;
        let signature = signatures::sign(
            method.as_str(),
            target.as_str(),
            body.as_deref().map_or(&[], |v| v.as_slice()),
            &key,
            &context.nonce,
            context.created,
        )
        .map_err(|_| ClientError::InvalidInput)?;
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let result = self
            .request_bytes(
                WireRequest {
                    method,
                    path: &path,
                    body: body.as_deref().map(|bytes| bytes.to_vec()),
                    token: Some(&token),
                    locale: "en",
                    signature: Some(signature),
                },
                &cancel,
            )
            .await;
        // Even a successful late response cannot publish an old local lifetime.
        self.validate_local_use(fence).await?;
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let (status, bytes) = result?;
        let bytes = zeroize::Zeroizing::new(bytes);
        if status.as_u16() != expected {
            return Err(ClientError::InvalidResponse);
        }
        Ok(bytes)
    }

    /// Native consumers only. This namespace never appears in the FFI surface;
    /// vault keys survive sign-out and are separate from device signing keys.
    pub fn vault_credentials(&self) -> Result<crate::SessionStore, ClientError> {
        self.device_store()?;
        let view = self.view();
        Ok(self.store.vault_store(&view.tenant_id, &view.user_id))
    }
    pub async fn sync_request(&self, request: SyncRequest) -> Result<SyncReply, ClientError> {
        use tracing::Instrument;
        if matches!(
            &request,
            SyncRequest::Telemetry(_)
                | SyncRequest::NativeTraces(_)
                | SyncRequest::TelemetryPolicy
                | SyncRequest::ObservabilityStatus
                | SyncRequest::Incidents { .. }
                | SyncRequest::IncidentAction { .. }
        ) {
            self.signed_request(request)
                .instrument(nddev_device_sync_telemetry::delivery_span())
                .await
        } else {
            self.signed_request(request).await
        }
    }
    async fn signed_request(&self, request: SyncRequest) -> Result<SyncReply, ClientError> {
        let (_permit, cancel) = self.operation().await?;
        let fence = if request.is_v3() || matches!(&request, SyncRequest::Company(_)) {
            Some(self.local_use_fence().await?)
        } else {
            self.authorize_local().await?;
            None
        };
        let store = self.device_store()?;
        let view = self.view();
        let current = view
            .devices
            .iter()
            .find(|device| device.is_current)
            .ok_or(ClientError::RevalidationRequired)?;
        if current.revoked {
            return Err(ClientError::DeviceRevoked);
        }
        let key = Key {
            key: crate::devices::read_key(&store)
                .await?
                .ok_or(ClientError::RevalidationRequired)?,
            id: current.device_id.clone(),
        };
        let token = self.session_credential().await?;
        if let Some(fence) = &fence {
            self.validate_local_use(fence).await?;
        }
        let (method, path, body) = request.prepare()?;
        let target = self
            .endpoint
            .join(&path)
            .map_err(|_| ClientError::InvalidEndpoint)?;
        let mut nonce = [0; 24];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ClientError::CredentialStore)?;
        let now = time::OffsetDateTime::now_utc()
            .unix_timestamp()
            .try_into()
            .map_err(|_| ClientError::InvalidInput)?;
        let signature = signatures::sign(
            method.as_str(),
            target.as_str(),
            body.as_deref().unwrap_or_default(),
            &key,
            &URL_SAFE_NO_PAD.encode(nonce),
            now,
        )
        .map_err(|_| ClientError::InvalidInput)?;
        let response = self
            .request_bytes(
                WireRequest {
                    method,
                    path: &path,
                    body,
                    token: Some(&token),
                    locale: "en",
                    signature: Some(signature),
                },
                &cancel,
            )
            .await;
        if let Some(fence) = &fence {
            self.validate_local_use(fence).await?;
            if cancel.is_cancelled() {
                return Err(ClientError::Cancelled);
            }
        }
        let (status, body) = response?;
        Ok(SyncReply {
            status: status.as_u16(),
            body,
        })
    }

    /// Privileged native provisioning only. Root keys never enter View or FFI.
    pub async fn ensure_vault_key(
        &self,
        existing: Option<&nddev_device_sync_domain::vault::KeyMaterial>,
    ) -> Result<nddev_device_sync_domain::vault::KeyMaterial, ClientError> {
        use zeroize::{Zeroize, Zeroizing};
        let mut request = crate::vault_wire::VaultKeyRequest {
            existing_key: existing.map(|key| crate::vault_wire::VaultKey {
                key_id: key.id(),
                key_material: URL_SAFE_NO_PAD.encode(key.expose()),
            }),
        };
        let body = serde_json::to_vec(&request).map_err(|_| ClientError::InvalidInput);
        if let Some(key) = &mut request.existing_key {
            key.key_material.zeroize();
        }
        let reply = self.sync_request(SyncRequest::VaultKey(body?)).await?;
        let bytes = Zeroizing::new(reply.body);
        if bytes.len() > 1024 {
            return Err(ClientError::InvalidResponse);
        }
        let status = reply.status;
        let reply: crate::vault_wire::VaultKey =
            serde_json::from_slice(&bytes).map_err(|_| ClientError::InvalidResponse)?;
        let encoded = Zeroizing::new(reply.key_material);
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.as_bytes())
                .map_err(|_| ClientError::InvalidResponse)?,
        );
        let key = nddev_device_sync_domain::vault::KeyMaterial::new(bytes.as_slice())
            .map_err(|_| ClientError::InvalidResponse)?;
        if status != 200
            || encoded.len() != 64
            || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != encoded.as_str()
            || key.id() != reply.key_id
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(key)
    }
}
