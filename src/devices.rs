//! Native device signing and the existing session-authorized enrollment protocol.
//! Keys are persisted before network mutations; uncertain responses are reconciled
//! against the retained public key, never by generating a replacement identity.
use crate::{ClientError, IdentityClient, View, device_wire as dto, view::DeviceView};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use http::{Method, StatusCode};
use nddev_device_sync_domain::devices::{DeviceName, ENROLLMENT_DOMAIN, MAX_DEVICE_IDENTITIES};
use ring::rand::{SecureRandom, SystemRandom};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

impl IdentityClient {
    pub(crate) fn device_store(&self) -> Result<crate::SessionStore, ClientError> {
        let view = self.view();
        if !view.authenticated
            || !(view.session_verified || view.offline_authorized)
            || view.credential_revalidation_required
        {
            return Err(ClientError::RevalidationRequired);
        }
        Ok(self.store.device_store(&view.tenant_id, &view.user_id))
    }

    pub(crate) async fn session_credential(&self) -> Result<crate::SessionCredential, ClientError> {
        self.stored_session_credential()
            .await?
            .ok_or(ClientError::RevalidationRequired)
    }

    pub(crate) async fn stored_session_credential(
        &self,
    ) -> Result<Option<crate::SessionCredential>, ClientError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let Some(secret) = self.store.read().await? else {
                return Ok(None);
            };
            let token = Zeroizing::new(
                String::from_utf8(secret.to_vec()).map_err(|_| ClientError::CredentialStore)?,
            );
            if !crate::valid_token(&token) {
                return Err(ClientError::CredentialStore);
            }
            Ok(Some(crate::SessionCredential::Bearer(token)))
        }
        #[cfg(target_arch = "wasm32")]
        {
            // Prove the browser credential backend is accessible without ever
            // trying to read or persist the HttpOnly session credential.
            self.store.offline_store(0).read().await?;
            Ok(Some(crate::SessionCredential::BrowserCookie))
        }
    }

    pub async fn refresh_devices(&self) -> Result<View, ClientError> {
        self.observe("device.inventory.refresh", async {
            let (_permit, cancel) = self.operation().await?;
            let store = self.device_store()?;
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .devices_checked_at = 0;
            let token = self.session_credential().await?;
            let key = read_key(&store).await?;
            let public = key
                .as_ref()
                .map(|key| URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()));
            self.update_devices(&token, public.as_deref(), &cancel)
                .await
        })
        .await
    }

    /// Sign-in prepares this installation automatically. Retained revoked
    /// signing keys are never replaced or re-enrolled as compensation.
    pub async fn prepare_device(&self, name: String) -> Result<View, ClientError> {
        let view = self.refresh_devices().await?;
        if let Some(current) = view.devices.iter().find(|device| device.is_current) {
            return if current.revoked {
                Err(ClientError::DeviceRevoked)
            } else {
                Ok(view)
            };
        }
        let name = if name.trim().is_empty() {
            format!("NDS {}", platform_name(&platform()))
        } else {
            name
        };
        self.enroll_device(name).await
    }

    pub async fn enroll_device(&self, name: String) -> Result<View, ClientError> {
        DeviceName::new(name.clone()).map_err(|_| ClientError::InvalidInput)?;
        self.observe("device.enrollment", async {
            let (_permit, cancel) = self.operation().await?;
            let store = self.device_store()?;
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .devices_checked_at = 0;
            let token = self.session_credential().await?;
            let key = match read_key(&store).await? {
                Some(key) => key,
                None => {
                    if cancel.is_cancelled() {
                        return Err(ClientError::Cancelled);
                    }
                    let mut seed = Zeroizing::new([0u8; 32]);
                    SystemRandom::new()
                        .fill(seed.as_mut())
                        .map_err(|_| ClientError::CredentialStore)?;
                    store.write(seed.as_slice()).await?;
                    // Verify the actual native write. A late write after cancellation
                    // remains available for the next enrollment reconciliation.
                    let restored = read_key(&store)
                        .await?
                        .ok_or(ClientError::CredentialStore)?;
                    if restored.verifying_key() != SigningKey::from_bytes(&seed).verifying_key() {
                        return Err(ClientError::CredentialStore);
                    }
                    restored
                }
            };
            let public = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
            let devices = self.device_inventory(&token, &cancel).await?;
            if let Some(existing) = devices.iter().find(|device| device.public_key == public) {
                let revoked = matches!(existing.status, dto::Status::Revoked);
                self.finish_devices(devices, Some(&public), &cancel)?;
                if revoked {
                    self.invalidate_offline(crate::store::FenceMode::Denied)
                        .await?;
                    return Err(ClientError::DeviceRevoked);
                }
                self.renew_authorization_inner(&cancel).await?;
                return Ok(self.view());
            }
            let platform = platform();
            let (status, bytes) = self
                .request(
                    Method::POST,
                    "/v2/devices/challenges",
                    Some(&dto::EnrollmentRequest {
                        display_name: name.clone(),
                        platform: platform.clone(),
                        public_key: public.clone(),
                    }),
                    Some(&token),
                    "en",
                    &cancel,
                )
                .await?;
            if status != StatusCode::CREATED {
                return Err(ClientError::InvalidResponse);
            }
            let challenge: dto::EnrollmentChallenge = crate::decode(&bytes)?;
            let proof = signing_bytes(&challenge)?;
            let signature = URL_SAFE_NO_PAD.encode(key.sign(&proof).to_bytes());
            let (status, bytes) = self
                .request(
                    Method::POST,
                    "/v2/devices/enrollments",
                    Some(&dto::EnrollmentProof {
                        challenge_id: challenge.challenge_id,
                        signature,
                    }),
                    Some(&token),
                    "en",
                    &cancel,
                )
                .await?;
            if status != StatusCode::CREATED {
                return Err(ClientError::InvalidResponse);
            }
            let device: dto::Device = crate::decode(&bytes)?;
            validate_device(&device)?;
            if device.device_id != challenge.device_id
                || device.public_key != public
                || device.display_name != name
                || platform_name(&device.platform) != platform_name(&platform)
                || !matches!(device.status, dto::Status::Active)
            {
                return Err(ClientError::InvalidResponse);
            }
            self.update_devices(&token, Some(&public), &cancel).await
        })
        .await
    }

    pub async fn revoke_device(&self, id: String) -> Result<View, ClientError> {
        if !crate::valid_token(&id) {
            return Err(ClientError::InvalidInput);
        }
        self.observe("device.revocation", async {
            let (_permit, cancel) = self.operation().await?;
            self.device_store()?;
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .devices_checked_at = 0;
            let token = self.session_credential().await?;
            if self.view().current_device_id == id {
                self.invalidate_offline(crate::store::FenceMode::Denied)
                    .await?;
            }
            let (status, _) = self
                .request::<()>(
                    Method::DELETE,
                    &format!("/v2/devices/{id}"),
                    None,
                    Some(&token),
                    "en",
                    &cancel,
                )
                .await?;
            if status != StatusCode::NO_CONTENT {
                return Err(ClientError::InvalidResponse);
            }
            // The server has committed the revocation. Apply that receipt
            // directly; later keyring/inventory I/O cannot undo its success.
            if let Some(device) = self
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .view
                .devices
                .iter_mut()
                .find(|device| device.device_id == id)
            {
                device.revoked = true;
            }
            Ok(self.view())
        })
        .await
    }

    async fn device_inventory(
        &self,
        token: &crate::SessionCredential,
        cancel: &CancellationToken,
    ) -> Result<Vec<dto::Device>, ClientError> {
        let mut devices = Vec::new();
        let mut after = 0;
        // Four bounded pages cover the authoritative 128 retained identities.
        for _ in 0..4 {
            let path = format!("/v2/devices?limit=32&cursor=devices.{after}");
            let page: dto::DeviceList = self.get(&path, Some(token), cancel).await?;
            if page.devices.len() > 32 || devices.len() + page.devices.len() > MAX_DEVICE_IDENTITIES
            {
                return Err(ClientError::InvalidResponse);
            }
            for device in &page.devices {
                validate_device(device)?;
                if devices.iter().any(|existing: &dto::Device| {
                    existing.device_id == device.device_id
                        || existing.public_key == device.public_key
                }) {
                    return Err(ClientError::InvalidResponse);
                }
                devices.push(device.clone());
            }
            match page.next_cursor {
                None => return Ok(devices),
                Some(cursor) => {
                    let next: usize = cursor
                        .strip_prefix("devices.")
                        .ok_or(ClientError::InvalidResponse)?
                        .parse()
                        .map_err(|_| ClientError::InvalidResponse)?;
                    if next <= after
                        || next > MAX_DEVICE_IDENTITIES
                        || cursor != format!("devices.{next}")
                        || page.devices.is_empty()
                    {
                        return Err(ClientError::InvalidResponse);
                    }
                    after = next;
                }
            }
        }
        Err(ClientError::InvalidResponse)
    }

    pub(crate) async fn update_devices(
        &self,
        token: &crate::SessionCredential,
        public: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<View, ClientError> {
        let devices = self.device_inventory(token, cancel).await?;
        let has_current = devices.iter().any(|device| {
            public == Some(device.public_key.as_str())
                && matches!(device.status, dto::Status::Active)
        });
        if !has_current
            && let Err(error) = self
                .invalidate_offline(crate::store::FenceMode::Denied)
                .await
        {
            self.require_revalidation();
            return Err(error);
        }
        self.finish_devices(devices, public, cancel)?;
        if has_current {
            self.renew_authorization_inner(cancel).await?;
        }
        Ok(self.view())
    }

    fn finish_devices(
        &self,
        devices: Vec<dto::Device>,
        public: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<View, ClientError> {
        let _completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let devices: Vec<_> = devices
            .into_iter()
            .map(|device| DeviceView {
                is_current: public == Some(device.public_key.as_str()),
                device_id: device.device_id,
                display_name: device.display_name,
                platform: platform_name(&device.platform).into(),
                revoked: matches!(device.status, dto::Status::Revoked),
                created_at: device.created_at,
            })
            .collect();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.view.current_device_id = devices
            .iter()
            .find(|device| device.is_current)
            .map(|device| device.device_id.clone())
            .unwrap_or_default();
        state.view.devices = devices;
        state.view.devices_checked_at = OffsetDateTime::now_utc().unix_timestamp();
        drop(state);
        Ok(self.view())
    }
}

pub(crate) async fn read_key(
    store: &crate::SessionStore,
) -> Result<Option<SigningKey>, ClientError> {
    store
        .read()
        .await?
        .map(|seed| {
            let bytes: &[u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::CredentialStore)?;
            Ok(SigningKey::from_bytes(bytes))
        })
        .transpose()
}
pub(crate) fn canonical_bytes<const N: usize>(value: &str) -> Result<[u8; N], ClientError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ClientError::InvalidResponse)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(ClientError::InvalidResponse);
    }
    bytes.try_into().map_err(|_| ClientError::InvalidResponse)
}
fn validate_device(device: &dto::Device) -> Result<(), ClientError> {
    if !crate::valid_token(&device.device_id) {
        return Err(ClientError::InvalidResponse);
    }
    DeviceName::new(device.display_name.clone()).map_err(|_| ClientError::InvalidResponse)?;
    let key = canonical_bytes(&device.public_key)?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| ClientError::InvalidResponse)?;
    if key.is_weak() {
        return Err(ClientError::InvalidResponse);
    }
    OffsetDateTime::parse(&device.created_at, &Rfc3339)
        .map_err(|_| ClientError::InvalidResponse)?;
    Ok(())
}
fn signing_bytes(challenge: &dto::EnrollmentChallenge) -> Result<Vec<u8>, ClientError> {
    if !crate::valid_token(&challenge.challenge_id) || !crate::valid_token(&challenge.device_id) {
        return Err(ClientError::InvalidResponse);
    }
    let expires = OffsetDateTime::parse(&challenge.expires_at, &Rfc3339)
        .map_err(|_| ClientError::InvalidResponse)?;
    let lifetime = expires - OffsetDateTime::now_utc();
    if lifetime <= time::Duration::ZERO || lifetime > time::Duration::seconds(330) {
        return Err(ClientError::Expired);
    }
    let mut bytes = ENROLLMENT_DOMAIN.to_vec();
    bytes.extend_from_slice(&canonical_bytes::<32>(&challenge.challenge)?);
    Ok(bytes)
}
fn platform_name(value: &dto::Platform) -> &'static str {
    match value {
        dto::Platform::Android => "android",
        dto::Platform::Ios => "ios",
        dto::Platform::Linux => "linux",
        dto::Platform::Macos => "macos",
        dto::Platform::Windows => "windows",
        dto::Platform::Web => "web",
    }
}
fn platform() -> dto::Platform {
    #[cfg(target_arch = "wasm32")]
    {
        dto::Platform::Web
    }
    #[cfg(target_os = "android")]
    {
        dto::Platform::Android
    }
    #[cfg(target_os = "ios")]
    {
        dto::Platform::Ios
    }
    #[cfg(target_os = "linux")]
    {
        dto::Platform::Linux
    }
    #[cfg(target_os = "macos")]
    {
        dto::Platform::Macos
    }
    #[cfg(target_os = "windows")]
    {
        dto::Platform::Windows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires an explicitly owned PostgreSQL/Mailpit fixture and unlocked native store"]
    async fn actual_enrollment_survives_client_recreation_and_revocation() {
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::env::var("NDS_FIXTURE_RECEIPT").unwrap()).unwrap(),
        )
        .unwrap();
        let endpoint = receipt["base_url"].as_str().unwrap();
        let mailbox = receipt["mailpit_url"].as_str().unwrap();
        let owner = receipt["owner_email"].as_str().unwrap();
        assert!(
            endpoint.starts_with("http://127.0.0.1:") && mailbox.starts_with("http://127.0.0.1:")
        );
        assert!(owner.ends_with(".invalid") || owner.ends_with(".test"));
        let client = IdentityClient::new(endpoint).unwrap();
        client.refresh().await.unwrap();
        client.request_email(owner.into(), "en").await.unwrap();
        let code = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let messages: serde_json::Value = client
                    .http
                    .get(format!("{mailbox}/api/v1/messages"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if let Some(id) = messages["messages"]
                    .as_array()
                    .and_then(|items| items.first())
                    .and_then(|value| value["ID"].as_str())
                {
                    let message: serde_json::Value = client
                        .http
                        .get(format!("{mailbox}/api/v1/message/{id}"))
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    if let Some((_, suffix)) =
                        message["Text"].as_str().unwrap().split_once("code: ")
                    {
                        break suffix.chars().take(8).collect::<String>();
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        client.verify_email(code).await.unwrap();
        let store = client.device_store().unwrap();
        let outcome = async {
            let first = client.enroll_device("Acceptance device".into()).await?;
            assert_eq!(first.devices.len(), 1);
            assert!(!first.current_device_id.is_empty());
            let id = uuid::Uuid::new_v4().to_string();
            let body = serde_json::to_vec(&serde_json::json!({
                "schema_version":2,"operation_id":id,"idempotency_key":id,
                "device_id":first.current_device_id,"entity_type":"vault_record",
                "entity_id":"native-transport-acceptance","base_revision":0,
                "payload":{"algorithm":"aes-256-gcm","key_id":"acceptance-key",
                "nonce":URL_SAFE_NO_PAD.encode([1;12]),"ciphertext":URL_SAFE_NO_PAD.encode([2;32])}
            }))
            .unwrap();
            let applied = client
                .sync_request(crate::SyncRequest::Append(body.clone()))
                .await?;
            assert_eq!(applied.status, 201);
            let retry = client
                .sync_request(crate::SyncRequest::Append(body.clone()))
                .await?;
            assert_eq!(retry.status, 201);
            assert_eq!(retry.body, applied.body);
            let page = client
                .sync_request(crate::SyncRequest::Page { after: 0, limit: 2 })
                .await?;
            assert_eq!(page.status, 200);
            let page: crate::sync_wire::SyncPage = serde_json::from_slice(&page.body).unwrap();
            assert_eq!(page.next_after_seq, 1);
            assert_eq!(page.entries.len(), 1);
            assert_eq!(
                serde_json::to_value(&page.entries[0].operation).unwrap(),
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()
            );
            let key_before = store.read().await?.unwrap();
            let again = IdentityClient::new(endpoint)?;
            again.refresh().await?;
            let restored = again.refresh_devices().await?;
            assert_eq!(restored.current_device_id, first.current_device_id);
            // Retry cannot create another identity even when the name differs.
            assert_eq!(
                again
                    .enroll_device("Retry name".into())
                    .await?
                    .devices
                    .len(),
                1
            );
            let revoked = again.revoke_device(first.current_device_id.clone()).await?;
            assert!(revoked.devices[0].revoked && revoked.devices[0].is_current);
            assert!(client.authorize_local().await.is_err());
            let cold = IdentityClient::new(endpoint)?;
            assert!(
                cold.restore_offline(&CancellationToken::new())
                    .await?
                    .is_none()
            );
            assert!(matches!(
                again.enroll_device("Another name".into()).await,
                Err(ClientError::DeviceRevoked)
            ));
            assert_eq!(
                store.read().await?.unwrap().as_slice(),
                key_before.as_slice()
            );
            again.logout().await?;
            assert_eq!(
                store.read().await?.unwrap().as_slice(),
                key_before.as_slice()
            );
            Ok::<_, ClientError>(())
        }
        .await;
        // This entry and server instance are generated solely by this fixture.
        store.delete().await.unwrap();
        client.store.delete().await.unwrap();
        outcome.unwrap();
    }
}
