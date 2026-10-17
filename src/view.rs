#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    #[error("invalid_endpoint")]
    InvalidEndpoint,
    #[error("invalid_input")]
    InvalidInput,
    #[error("telemetry_unavailable")]
    TelemetryUnavailable,
    #[error("invalid_response")]
    InvalidResponse,
    #[error("transport_unavailable")]
    Transport,
    #[error("request_timeout")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
    #[error("busy")]
    Busy,
    #[error("credential_store_unavailable")]
    CredentialStore,
    #[error("credential_revalidation_required")]
    RevalidationRequired,
    #[error("challenge_expired")]
    Expired,
    #[error("device_revoked")]
    DeviceRevoked,
    #[error("{0}")]
    Server(String),
}

impl ClientError {
    /// An allowlisted code for localization; never an underlying I/O message.
    pub fn code(&self) -> String {
        self.to_string()
    }
}

/// Presentation state, never a bearer credential or a wire request.
#[derive(Clone, Default)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct View {
    pub invitation_pending: bool,
    pub devices: Vec<DeviceView>,
    pub current_device_id: String,
    pub devices_checked_at: i64,
    pub email_available: bool,
    pub github_available: bool,
    pub passkey_available: bool,
    pub credential_store_ready: bool,
    pub server_version: String,
    pub authenticated: bool,
    pub session_verified: bool,
    pub offline_authorized: bool,
    pub offline_cache_ready: bool,
    pub logout_pending: bool,
    pub credential_revalidation_required: bool,
    pub session_checked_at: i64,
    pub user_id: String,
    pub tenant_id: String,
    pub auth_method: String,
    pub expires_at: String,
    pub flow: String,
    pub authorization_url: String,
    pub verification_code: String,
    pub expires_in_seconds: u32,
    pub retry_after_seconds: u32,
}

/// Public metadata only; signing keys never cross the presentation boundary.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct DeviceView {
    pub device_id: String,
    pub display_name: String,
    pub platform: String,
    pub revoked: bool,
    pub is_current: bool,
    pub created_at: String,
}

impl std::fmt::Debug for View {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("View")
            .field("authenticated", &self.authenticated)
            .field("session_verified", &self.session_verified)
            .field(
                "credential_revalidation_required",
                &self.credential_revalidation_required,
            )
            .finish_non_exhaustive()
    }
}

/// Bounded public credential metadata; no verifier/public-key bodies or secrets.
#[derive(Clone)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct PasskeyView {
    pub id: String,
    pub created_at: String,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub enum ExportPolicy {
    #[default]
    Unknown,
    Enabled,
    Disabled,
}
#[derive(Clone, Default)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct DeliveryView {
    pub initialized: bool,
    /// Browser durable-spool availability; native transport does not use it.
    pub local_persistence_ready: Option<bool>,
    pub policy: ExportPolicy,
    pub paused: bool,
    pub pending: u32,
    pub delivered: u64,
    pub dropped: u64,
    pub failures: u64,
    pub spans_pending: u32,
    pub spans_delivered: u64,
    pub spans_dropped: u64,
    pub spans_failures: u64,
    pub last_success_at: u64,
}
