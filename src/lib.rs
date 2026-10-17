//! NDS identity HTTP client. Secrets stay in Rust and native credential stores.
pub mod company;
pub mod company_wire;
pub mod device_wire;
pub mod invitation;
pub mod observability_wire;
pub mod screen;
pub mod screen_wire;
mod sync;
pub mod sync3_wire;
pub mod sync_wire;
pub mod telemetry;
pub mod vault_wire;
pub use sync::{SyncExpiry, SyncReply, SyncRequest};
mod devices;
pub mod health_wire;
mod offline;
pub use offline::{LocalUseFence, LocalUseLifetime};
pub mod runtime;
mod store;
mod transport;
use runtime::Instant;
pub mod wire;
pub use store::SessionStore;
#[cfg(not(target_arch = "wasm32"))]
mod paths;
#[cfg(not(target_arch = "wasm32"))]
pub use paths::private_data_directory;
#[cfg(target_os = "android")]
pub mod android;

use http::{Method, StatusCode};
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use store::OperationPermit;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use url::{Host, Url};
use zeroize::Zeroizing;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 65_536;

/// Transport credential ownership is explicit. Browser code cannot substitute
/// a made-up bearer value for the HttpOnly cookie owned by the browser.
enum SessionCredential {
    #[cfg(not(target_arch = "wasm32"))]
    Bearer(Zeroizing<String>),
    #[cfg(target_arch = "wasm32")]
    BrowserCookie,
}

#[cfg(not(target_arch = "wasm32"))]
type IssuedSession = wire::SessionIssued;
#[cfg(target_arch = "wasm32")]
type IssuedSession = wire::BrowserSessionIssued;

pub mod view;
pub use view::{ClientError, View};

struct WireRequest<'a> {
    method: Method,
    path: &'a str,
    body: Option<Vec<u8>>,
    token: Option<&'a SessionCredential>,
    locale: &'a str,
    signature: Option<nddev_device_sync_http_signatures::Headers>,
}

enum Flow {
    Email {
        id: String,
        expires: Instant,
        resend: Instant,
    },
    Browser {
        passkey: bool,
        registration: bool,
        id: String,
        token: Zeroizing<String>,
        expires: Instant,
        next_poll: Instant,
    },
}

#[derive(Default)]
struct State {
    invitation: Option<invitation::InvitationLink>,
    view: View,
    flow: Option<Flow>,
    session_deadline: Option<Instant>,
    // Local-use handles expire on client cancellation, independently of request
    // tokens that rotate for each NDS operation. No authority is stored here.
    local_use_generation: Arc<()>,
    rds_key: std::sync::Weak<Mutex<Option<screen::KeyMaterial>>>,
}

/// One bounded operation per client; concurrent calls fail instead of queuing.
pub struct IdentityClient {
    endpoint: Url,
    #[cfg(not(target_arch = "wasm32"))]
    http: reqwest::Client,
    store: SessionStore,
    state: Mutex<State>,
    cancellation: Mutex<CancellationToken>,
}

impl Drop for IdentityClient {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl IdentityClient {
    pub fn origin(&self) -> String {
        self.endpoint.as_str().into()
    }
    pub fn new(endpoint: &str) -> Result<Self, ClientError> {
        let endpoint = validate_endpoint(endpoint)?;
        #[cfg(not(target_arch = "wasm32"))]
        let http = {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut builder = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(1);
            if endpoint.scheme() == "http" {
                builder = builder.no_proxy();
            }
            builder.build().map_err(|_| ClientError::Transport)?
        };
        #[cfg(target_arch = "wasm32")]
        transport::browser::validate_origin(&endpoint)?;
        Ok(Self {
            store: SessionStore::for_endpoint(endpoint.as_str())?,
            endpoint,
            #[cfg(not(target_arch = "wasm32"))]
            http,
            state: Mutex::new(State::default()),
            cancellation: Mutex::new(CancellationToken::new()),
        })
    }

    pub fn cancel(&self) {
        self.cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.local_use_generation = Arc::default();
        screen::close_key(&mut state);
    }

    pub fn view(&self) -> View {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        expire_session(&mut state, now, OffsetDateTime::now_utc());
        if state.flow.as_ref().is_some_and(|flow| match flow {
            Flow::Email { expires, .. } | Flow::Browser { expires, .. } => *expires <= now,
        }) {
            clear_flow_state(&mut state);
        }
        let mut view = state.view.clone();
        view.invitation_pending = state.invitation.is_some();
        if let Some(flow) = &state.flow {
            let (expires, retry) = match flow {
                Flow::Email {
                    expires, resend, ..
                } => (*expires, *resend),
                Flow::Browser {
                    expires, next_poll, ..
                } => (*expires, *next_poll),
            };
            view.expires_in_seconds = remaining(expires);
            view.retry_after_seconds = remaining(retry);
        }
        view
    }

    async fn operation(&self) -> Result<(OperationPermit, CancellationToken), ClientError> {
        let permit = self.store.operation()?;
        let token = CancellationToken::new();
        *self.cancellation.lock().unwrap_or_else(|e| e.into_inner()) = token.clone();
        let permit = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(ClientError::Cancelled),
            result = self.store.activate_operation(permit) => result?,
        };
        Ok((permit, token))
    }

    async fn observe(
        &self,
        event: &'static str,
        operation: impl std::future::Future<Output = Result<View, ClientError>>,
    ) -> Result<View, ClientError> {
        let span = nddev_device_sync_telemetry::operation_span("accounts", "process")
            .map_err(|_| ClientError::TelemetryUnavailable)?;
        async {
            let started = Instant::now();
            let result = operation.await;
            nddev_device_sync_telemetry::finish_operation_span(
                &tracing::Span::current(),
                result.as_ref().is_err_and(terminal_identity_failure),
            );
            match &result {
                Ok(view) => tracing::event!(target:"nds_accounts",tracing::Level::INFO, {
                    event.name=event,duration_ms=started.elapsed().as_millis() as u64,outcome=if view.logout_pending {"pending"} else {"ok"}
                }),
                Err(error) => tracing::event!(target:"nds_accounts",tracing::Level::WARN, {
                    event.name=event,duration_ms=started.elapsed().as_millis() as u64,error.type=error.code(),outcome="error"
                }),
            }
            result
        }.instrument(span).await
    }

    pub async fn refresh(&self) -> Result<View, ClientError> {
        self.observe("identity.refresh", self.refresh_operation())
            .await
    }

    async fn refresh_operation(&self) -> Result<View, ClientError> {
        let (_permit, cancel) = self.operation().await?;
        let result = self.refresh_online(&cancel).await;
        if matches!(&result, Err(ClientError::Transport | ClientError::Timeout))
            && let Some(view) = self.restore_offline(&cancel).await?
        {
            return Ok(view);
        }
        if matches!(&result, Err(ClientError::InvalidResponse)) {
            self.require_revalidation();
        }
        result
    }

    async fn refresh_online(&self, cancel: &CancellationToken) -> Result<View, ClientError> {
        let signed_out = self.finish_pending_logout(cancel).await?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .session_verified = false;
        let health: health_wire::HealthResponse = self.get("/v1/health", None, cancel).await?;
        #[cfg(target_arch = "wasm32")]
        {
            // Negotiate the cookie boundary before exposing sign-in actions.
            // An older bearer-only server must not issue its token to a browser.
            let capabilities: wire::BrowserCapabilities =
                self.get("/v2/browser", None, cancel).await?;
            if capabilities.replica_protocol != 2 {
                return Err(ClientError::InvalidResponse);
            }
        }
        let methods: wire::AuthMethods = self.get("/v2/auth/methods", None, cancel).await?;
        {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.view.server_version = health.version;
            s.view.email_available =
                matches!(methods.email_otp, wire::MethodAvailability::Available);
            s.view.github_available = matches!(methods.github, wire::MethodAvailability::Available);
            s.view.passkey_available =
                matches!(methods.passkey, wire::MethodAvailability::Available);
        }
        if signed_out {
            return Ok(self.view());
        }
        let credential = self.stored_session_credential().await;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .credential_store_ready = credential.is_ok();
        if let Some(token) = credential? {
            match self
                .get::<wire::Session>("/v2/session", Some(&token), cancel)
                .await
            {
                Ok(session) => {
                    let deadline = validate_session(&session)?;
                    self.finish_persisted_session(session, deadline, cancel, true)?;
                }
                Err(ClientError::Server(code)) if code == "authentication_failed" => {
                    #[cfg(not(target_arch = "wasm32"))]
                    self.store.delete().await?;
                    self.clear_session();
                }
                Err(error) => return Err(error),
            }
        } else {
            self.clear_session();
        }
        Ok(self.view())
    }

    pub async fn request_email(&self, email: String, locale: &str) -> Result<View, ClientError> {
        self.observe(
            "identity.email.request",
            self.request_email_operation(email, locale),
        )
        .await
    }

    async fn request_email_operation(
        &self,
        email: String,
        locale: &str,
    ) -> Result<View, ClientError> {
        if !(3..=254).contains(&email.len()) {
            return Err(ClientError::InvalidInput);
        }
        self.require_store_ready()?;
        let (_permit, cancel) = self.operation().await?;
        self.finish_pending_logout(&cancel).await?;
        {
            let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(s.flow, Some(Flow::Email {resend, ..}) if resend > Instant::now()) {
                return Err(ClientError::Server("rate_limited".into()));
            }
        }
        let invitation_body = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state
                .invitation
                .as_ref()
                .map(|link| link.body(email.clone()))
                .transpose()?
        };
        let response: wire::EmailChallenge = if let Some(body) = invitation_body {
            let (status, bytes) = self
                .request_bytes(
                    WireRequest {
                        method: Method::POST,
                        path: "/v2/auth/invitations/challenges",
                        body: Some(body),
                        token: None,
                        locale,
                        signature: None,
                    },
                    &cancel,
                )
                .await?;
            if status != StatusCode::ACCEPTED {
                return Err(ClientError::InvalidResponse);
            }
            decode(&bytes)?
        } else {
            self.post(
                "/v2/auth/email/challenges",
                &wire::EmailChallengeRequest { email },
                StatusCode::ACCEPTED,
                locale,
                &cancel,
            )
            .await?
        };
        let expires = lifetime(response.expires_in_seconds, 600)?;
        let resend = lifetime(response.resend_after_seconds, 600)?;
        if !valid_id(&response.challenge_id) {
            return Err(ClientError::InvalidResponse);
        }
        self.finish_flow(
            Flow::Email {
                id: response.challenge_id,
                expires,
                resend,
            },
            String::new(),
            String::new(),
            &cancel,
        )?;
        Ok(self.view())
    }

    pub async fn verify_email(&self, code: String) -> Result<View, ClientError> {
        self.observe("identity.email.verify", self.verify_email_operation(code))
            .await
    }

    async fn verify_email_operation(&self, code: String) -> Result<View, ClientError> {
        if code.len() != 8 || !code.bytes().all(|c| c.is_ascii_digit()) {
            return Err(ClientError::InvalidInput);
        }
        let (_permit, cancel) = self.operation().await?;
        let id = {
            let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match &s.flow {
                Some(Flow::Email { id, expires, .. }) if *expires > Instant::now() => id.clone(),
                _ => return Err(ClientError::Expired),
            }
        };
        let issued = self
            .post(
                "/v2/auth/email/verify",
                &wire::EmailVerifyRequest {
                    challenge_id: id,
                    code,
                },
                StatusCode::OK,
                "en",
                &cancel,
            )
            .await?;
        self.accept_session(issued, &cancel).await?;
        Ok(self.view())
    }

    pub async fn start_github(&self, locale: &str) -> Result<View, ClientError> {
        self.observe("identity.github.start", self.start_github_operation(locale))
            .await
    }

    async fn start_github_operation(&self, locale: &str) -> Result<View, ClientError> {
        self.require_store_ready()?;
        let (_permit, cancel) = self.operation().await?;
        self.finish_pending_logout(&cancel).await?;
        let response: wire::GithubStart = self
            .post(
                "/v2/auth/github/start",
                &serde_json::json!({}),
                StatusCode::OK,
                locale,
                &cancel,
            )
            .await?;
        validate_github_url(&response.authorization_url, &self.endpoint)?;
        if !valid_token(&response.exchange_token)
            || !valid_id(&response.flow_id)
            || response.verification_code.len() != 8
            || !response
                .verification_code
                .bytes()
                .all(|c| c.is_ascii_digit())
        {
            return Err(ClientError::InvalidResponse);
        }
        let expires = lifetime(response.expires_in_seconds, 600)?;
        let next_poll = lifetime(response.poll_after_seconds, 30)?;
        self.finish_flow(
            Flow::Browser {
                passkey: false,
                registration: false,
                id: response.flow_id,
                token: Zeroizing::new(response.exchange_token),
                expires,
                next_poll,
            },
            response.authorization_url,
            response.verification_code,
            &cancel,
        )?;
        Ok(self.view())
    }

    /// Native/browser WebAuthn flow; exchange tokens never leave this module.
    pub async fn passkeys(&self) -> Result<Vec<view::PasskeyView>, ClientError> {
        let (_permit, cancel) = self.operation().await?;
        let token = self.session_credential().await?;
        let page: wire::PasskeyList = self.get("/v2/auth/passkeys", Some(&token), &cancel).await?;
        if page.passkeys.len() > 16 {
            return Err(ClientError::InvalidResponse);
        }
        page.passkeys
            .into_iter()
            .map(|key| {
                if !passkey_id(&key.id) || OffsetDateTime::parse(&key.created_at, &Rfc3339).is_err()
                {
                    return Err(ClientError::InvalidResponse);
                }
                Ok(view::PasskeyView {
                    id: key.id,
                    created_at: key.created_at,
                })
            })
            .collect()
    }
    pub async fn revoke_passkey(&self, id: String) -> Result<View, ClientError> {
        self.observe("identity.passkey.revoke", async {
            if !passkey_id(&id) {
                return Err(ClientError::InvalidInput);
            }
            let (_permit, cancel) = self.operation().await?;
            let token = self.session_credential().await?;
            // The chosen passkey may own this session. Block cached access
            // before the mutation; a lost response cannot revive that session.
            let previous=self.store.authorization_fence(None).await?;
            let pending=store::Fence::new(store::FenceMode::Checking)?;
            self.store.authorization_fence(Some((previous.clone(),pending.clone()))).await?;
            {let mut state=self.state.lock().unwrap_or_else(|e|e.into_inner());state.view.offline_authorized=false;state.view.offline_cache_ready=false;}
            let response = self
                .request::<()>(
                    Method::DELETE,
                    &format!("/v2/auth/passkeys/{id}"),
                    None,
                    Some(&token),
                    "en",
                    &cancel,
                )
                .await;
            let (status,body)=match response {
                Ok(value)=>value,
                Err(error)=>{
                    if matches!(&error,ClientError::Server(code) if code=="recent_authentication_required") {
                        self.restore_passkey_authorization(previous,pending).await?;
                    }
                    return Err(error);
                }
            };
            if status != StatusCode::OK {
                return Err(ClientError::InvalidResponse);
            }
            let receipt: wire::PasskeyRevocation = decode(&body)?;
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .view
                .passkey_available = receipt.passkey_available;
            if receipt.current_session_revoked {
                self.clear_session();
                self.clear_flow();
            } else if self.restore_passkey_authorization(previous,pending).await.is_err() {
                tracing::event!(target:"nds_accounts",tracing::Level::WARN,{event.name="identity.offline.restore_failed",error.type="credential_store_unavailable",outcome="error"});
            }
            // An invalidated cached token is removed on the next ordinary
            // refresh. No fallible I/O follows this authoritative receipt.
            Ok(self.view())
        })
        .await
    }
    async fn restore_passkey_authorization(
        &self,
        previous: Option<store::Fence>,
        pending: store::Fence,
    ) -> Result<(), ClientError> {
        if let Some(previous) = previous {
            self.store
                .authorization_fence(Some((Some(pending), previous.clone())))
                .await?;
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.view.offline_cache_ready = previous.mode == store::FenceMode::Ready;
            state.view.offline_authorized = state.view.offline_cache_ready
                && state.view.authenticated
                && !state.view.session_verified;
        }
        Ok(())
    }
    pub async fn start_passkey(
        &self,
        registration: bool,
        email: Option<String>,
        locale: &str,
    ) -> Result<View, ClientError> {
        self.observe("identity.passkey.start", async {
            let request = passkey_request(registration, email)?;
            self.require_store_ready()?;
            let (_permit, cancel) = self.operation().await?;
            self.finish_pending_logout(&cancel).await?;
            let retained = if registration {
                Some(self.session_credential().await?)
            } else {
                None
            };
            let token = retained.as_ref();
            let (status, body) = self
                .request(
                    Method::POST,
                    "/v2/auth/passkeys/start",
                    Some(&request),
                    token,
                    locale,
                    &cancel,
                )
                .await?;
            if status != StatusCode::OK {
                return Err(ClientError::InvalidResponse);
            }
            let response: wire::PasskeyStart = decode(&body)?;
            let url = Url::parse(&response.authorization_url)
                .map_err(|_| ClientError::InvalidResponse)?;
            if url.origin() != self.endpoint.origin()
                || url.path() != "/v2/auth/passkeys/browser"
                || url.fragment().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query() != Some(format!("flow_id={}", response.flow_id).as_str())
                || !valid_token(&response.exchange_token)
                || !valid_id(&response.flow_id)
                || response.verification_code.len() != 8
                || !response
                    .verification_code
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
            {
                return Err(ClientError::InvalidResponse);
            }
            self.finish_flow(
                Flow::Browser {
                    passkey: true,
                    registration,
                    id: response.flow_id,
                    token: Zeroizing::new(response.exchange_token),
                    expires: lifetime(response.expires_in_seconds, 300)?,
                    next_poll: lifetime(response.poll_after_seconds, 30)?,
                },
                response.authorization_url,
                response.verification_code,
                &cancel,
            )?;
            Ok(self.view())
        })
        .await
    }

    pub async fn poll_passkey(&self) -> Result<View, ClientError> {
        self.observe("identity.passkey.poll", self.poll_github_operation())
            .await
    }

    pub async fn poll_github(&self) -> Result<View, ClientError> {
        self.observe("identity.github.poll", self.poll_github_operation())
            .await
    }

    async fn poll_github_operation(&self) -> Result<View, ClientError> {
        let (_permit, cancel) = self.operation().await?;
        let (request, passkey, registration) = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match &mut s.flow {
                Some(Flow::Browser {
                    passkey,
                    registration,
                    id,
                    token,
                    expires,
                    next_poll,
                }) if *expires > Instant::now() => {
                    if *next_poll > Instant::now() {
                        drop(s);
                        return Ok(self.view());
                    }
                    *next_poll = Instant::now() + Duration::from_secs(2);
                    (
                        wire::GithubExchangeRequest {
                            flow_id: id.clone(),
                            exchange_token: token.to_string(),
                        },
                        *passkey,
                        *registration,
                    )
                }
                _ => return Err(ClientError::Expired),
            }
        };
        let result = self
            .request(
                Method::POST,
                if passkey {
                    "/v2/auth/passkeys/exchange"
                } else {
                    "/v2/auth/github/exchange"
                },
                Some(&request),
                None,
                "en",
                &cancel,
            )
            .await;
        let (status, body) = match result {
            Err(error @ ClientError::Server(_)) => {
                self.clear_flow();
                return Err(error);
            }
            other => other?,
        };
        if status == StatusCode::ACCEPTED {
            let retry = if passkey {
                let pending: wire::PasskeyStatus = decode(&body)?;
                if !matches!(pending.status, wire::PasskeyStatusStatus::Pending) {
                    return Err(ClientError::InvalidResponse);
                }
                pending.retry_after_seconds
            } else {
                decode::<wire::GithubPending>(&body)?.retry_after_seconds
            };
            let next = lifetime(retry, 30)?;
            if let Some(Flow::Browser { next_poll, .. }) =
                &mut self.state.lock().unwrap_or_else(|e| e.into_inner()).flow
            {
                *next_poll = next;
            }
        } else if status == StatusCode::OK {
            if registration {
                let completion: wire::PasskeyStatus = decode(&body)?;
                if !matches!(completion.status, wire::PasskeyStatusStatus::Registered)
                    || completion.retry_after_seconds != 0
                {
                    return Err(ClientError::InvalidResponse);
                }
                self.clear_flow();
                self.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .view
                    .passkey_available = true;
            } else {
                self.accept_session(decode(&body)?, &cancel).await?;
            }
        } else {
            return Err(ClientError::InvalidResponse);
        }
        Ok(self.view())
    }

    pub fn cancel_sign_in(&self) {
        let completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        completion.cancel();
        self.clear_flow();
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .local_use_generation = Arc::default();
    }

    fn finish_flow(
        &self,
        flow: Flow,
        authorization_url: String,
        verification_code: String,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let _completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.view.flow = match &flow {
            Flow::Email { .. } => "email",
            Flow::Browser {
                passkey: true,
                registration: true,
                ..
            } => "passkey_registration",
            Flow::Browser { passkey: true, .. } => "passkey",
            Flow::Browser { .. } => "github",
        }
        .into();
        state.flow = Some(flow);
        state.view.authorization_url = authorization_url;
        state.view.verification_code = verification_code;
        Ok(())
    }

    pub async fn logout(&self) -> Result<View, ClientError> {
        self.observe("identity.logout", self.logout_operation())
            .await
    }

    async fn logout_operation(&self) -> Result<View, ClientError> {
        let (_permit, cancel) = self.operation().await?;
        self.invalidate_offline(store::FenceMode::PendingLogout)
            .await?;
        self.clear_session();
        self.clear_flow();
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .logout_pending = true;
        match self.finish_pending_logout(&cancel).await {
            Ok(_) => Ok(self.view()),
            Err(ClientError::Transport | ClientError::Timeout) => Ok(self.view()),
            Err(error) => Err(error),
        }
    }

    async fn accept_session(
        &self,
        response: IssuedSession,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let deadline = validate_session(&response.session)?;
        self.invalidate_offline(store::FenceMode::Checking).await?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .logout_pending = false;
        #[cfg(not(target_arch = "wasm32"))]
        if !valid_token(&response.session_token) {
            return Err(ClientError::InvalidResponse);
        }
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        #[cfg(not(target_arch = "wasm32"))]
        let persistence = self
            .store
            .write(Zeroizing::new(response.session_token).as_bytes())
            .await;
        #[cfg(target_arch = "wasm32")]
        let persistence = self.store.offline_store(0).read().await.map(|_| ());
        if let Err(error) = persistence {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .credential_store_ready = false;
            self.require_revalidation();
            return Err(error);
        }
        self.finish_persisted_session(response.session, deadline, cancel, false)
    }

    fn finish_persisted_session(
        &self,
        session: wire::Session,
        deadline: Instant,
        cancel: &CancellationToken,
        preserve_devices: bool,
    ) -> Result<(), ClientError> {
        let completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() || deadline <= Instant::now() {
            // The OS write can finish after cancellation. Preserve the secret,
            // expose uncertainty and require server revalidation, not a false
            // authenticated/signed-out result or destructive compensation.
            drop(completion);
            self.require_revalidation();
            return Err(ClientError::RevalidationRequired);
        }
        self.set_session(session, deadline, preserve_devices);
        self.clear_flow();
        drop(completion);
        Ok(())
    }

    fn set_session(&self, session: wire::Session, deadline: Instant, preserve_devices: bool) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let preserve_devices = preserve_devices
            && s.view.user_id == session.user_id
            && s.view.tenant_id == session.tenant_id;
        s.session_deadline = Some(deadline);
        s.view.authenticated = true;
        s.view.session_verified = true;
        s.view.offline_authorized = false;
        // A successful refresh of the same owner is not a new sign-in. Keep
        // the last device observation until the inventory refresh replaces it.
        // Local operations still consult the protected grant on every use.
        if !preserve_devices {
            // A newly accepted sign-in owns a new local lifetime, even for the
            // same owner. Late work from the preceding session cannot publish.
            s.local_use_generation = Arc::default();
            s.view.offline_cache_ready = false;
            s.view.current_device_id.clear();
            s.view.devices.clear();
            s.view.devices_checked_at = 0;
        }
        s.view.credential_revalidation_required = false;
        s.view.session_checked_at = OffsetDateTime::now_utc().unix_timestamp();
        s.view.user_id = session.user_id;
        s.view.tenant_id = session.tenant_id;
        s.view.expires_at = session.expires_at;
        s.view.auth_method = match session.auth_method {
            wire::AuthMethod::EmailOtp => "email_otp",
            wire::AuthMethod::Github => "github",
            wire::AuthMethod::Passkey => "passkey",
        }
        .into();
    }

    fn clear_session(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        screen::close_key(&mut s);
        s.session_deadline = None;
        s.view.authenticated = false;
        s.view.session_verified = false;
        s.view.offline_authorized = false;
        s.view.offline_cache_ready = false;
        s.view.credential_revalidation_required = false;
        s.view.session_checked_at = 0;
        s.view.user_id.clear();
        s.view.tenant_id.clear();
        s.view.expires_at.clear();
        s.view.auth_method.clear();
        s.view.devices.clear();
        s.view.current_device_id.clear();
        s.view.devices_checked_at = 0;
    }

    fn require_revalidation(&self) {
        self.clear_flow();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.view.session_verified = false;
        screen::close_key(&mut state);
        state.view.credential_revalidation_required = true;
        state.view.offline_authorized = false;
        state.view.offline_cache_ready = false;
    }

    fn require_store_ready(&self) -> Result<(), ClientError> {
        if !self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .credential_store_ready
        {
            return Err(ClientError::CredentialStore);
        }
        Ok(())
    }

    fn clear_flow(&self) {
        clear_flow_state(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&SessionCredential>,
        cancel: &CancellationToken,
    ) -> Result<T, ClientError> {
        let (status, body) = self
            .request::<()>(Method::GET, path, None, token, "en", cancel)
            .await?;
        if status != StatusCode::OK {
            return Err(ClientError::InvalidResponse);
        }
        decode(&body)
    }

    async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        expected_status: StatusCode,
        locale: &str,
        cancel: &CancellationToken,
    ) -> Result<R, ClientError> {
        let (status, body) = self
            .request(Method::POST, path, Some(body), None, locale, cancel)
            .await?;
        if status != expected_status {
            return Err(ClientError::InvalidResponse);
        }
        decode(&body)
    }

    async fn request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        token: Option<&SessionCredential>,
        locale: &str,
        cancel: &CancellationToken,
    ) -> Result<(StatusCode, Vec<u8>), ClientError> {
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| ClientError::InvalidInput)?;
        self.request_bytes(
            WireRequest {
                method,
                path,
                body,
                token,
                locale,
                signature: None,
            },
            cancel,
        )
        .await
    }

    async fn request_bytes(
        &self,
        options: WireRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<(StatusCode, Vec<u8>), ClientError> {
        let WireRequest {
            method,
            path,
            body,
            token,
            locale,
            signature,
        } = options;
        if body.as_ref().is_some_and(|body| body.len() > MAX_BODY) {
            return Err(ClientError::InvalidInput);
        }
        let signed = signature.is_some();
        let capabilities_request = signed && method == Method::GET && path == "/v3/sync";
        let span = if path.starts_with("/v2/observability/") {
            tracing::Span::none()
        } else {
            nddev_device_sync_telemetry::operation_span("accounts", "http")
                .map_err(|_| ClientError::TelemetryUnavailable)?
        };
        let context = nddev_device_sync_telemetry::trace_context(&span);
        // Normalize device paths before recording them; queries and IDs stay out.
        let route = if let Some(route) =
            screen::route_template(path).or_else(|| company::route_template(path))
        {
            route
        } else if path.starts_with("/v2/devices/")
            && !matches!(path, "/v2/devices/challenges" | "/v2/devices/enrollments")
        {
            "/v2/devices/{device_id}"
        } else if method == Method::DELETE && path.starts_with("/v2/auth/passkeys/") {
            "/v2/auth/passkeys/{id}"
        } else {
            path.split('?').next().unwrap_or("unknown")
        };
        async {
        let started = Instant::now();
        tracing::event!(target: "nds_accounts", tracing::Level::DEBUG,
            { event.name = "identity.request_started", route });
        let mut propagation = std::collections::HashMap::new();
        TraceContextPropagator::new().inject_context(&context, &mut propagation);
        let operation = async {
            let (status, bytes) = self.transport_request(WireRequest {
                method, path, body, token, locale, signature,
            }, propagation).await?;
            if signed {
                sync::validate_v3_reply_size(path, status, bytes.len())?;
            }
            if !status.is_success() {
                // Older servers have no capabilities route. Preserve only this
                // fixed-route absence; Core still owns writer-mode admission.
                if capabilities_request && status == StatusCode::NOT_FOUND {
                    return Ok((status, bytes));
                }
                // Lifecycle expiration is a typed Unknown result. Keep its exact
                // response bytes; transport never changes durable pending work.
                if signed && status == StatusCode::GONE {
                    let route = path.split('?').next().unwrap_or_default();
                    if matches!(route, "/v3/sync/operations" | "/v3/sync/history" | "/v3/sync/base") {
                        sync::decode_expired_v3(&bytes)?;
                        return Ok((status, bytes));
                    }
                    if route == "/v2/sync/operations" {
                        sync::decode_expired_v2(&bytes)?;
                        return Ok((status, bytes));
                    }
                }
                // A retained revision conflict is a sync result, not a generic
                // error. Preserve its exact bytes for the durable client inbox.
                if signed && status==StatusCode::CONFLICT && matches!(serde_json::from_slice::<sync_wire::Sync>(&bytes), Ok(sync_wire::Sync::Conflict(_))) {
                    return Ok((status,bytes));
                }
                let code = if path.starts_with("/v2/company") {
                    let response: company_wire::CompanyError = decode(&bytes)?;
                    serde_json::to_value(response.error)
                } else {
                    let response: wire::Error = decode(&bytes)?;
                    serde_json::to_value(response.error)
                }.map_err(|_| ClientError::InvalidResponse)?;
                if token.is_some() && code.as_str() == Some("authentication_failed") {
                    self.require_revalidation();
                    self.invalidate_offline(store::FenceMode::Denied).await?;
                }
                if token.is_some() && code.as_str() == Some("device_revoked") {
                    for device in &mut self.state.lock().unwrap_or_else(|e| e.into_inner()).view.devices {
                        if device.is_current { device.revoked = true; }
                    }
                    self.invalidate_offline(store::FenceMode::Denied).await?;
                    return Err(ClientError::DeviceRevoked);
                }
                return Err(ClientError::Server(
                    code.as_str()
                        .ok_or(ClientError::InvalidResponse)?
                        .to_owned(),
                ));
            }
            Ok((status, bytes))
        };
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ClientError::Cancelled),
            result = runtime::timeout(REQUEST_TIMEOUT, operation) => result.unwrap_or(Err(ClientError::Timeout)),
        };
        match &result {
            Ok((status, _)) => tracing::event!(target: "nds_accounts", tracing::Level::INFO,
                { event.name = "identity.request_completed", route, status = status.as_u16(),
                  duration_ms = started.elapsed().as_millis() as u64, outcome = "ok" }),
            Err(error) => tracing::event!(target: "nds_accounts", tracing::Level::WARN,
                { event.name = "identity.request_completed", route, error.type = error.code(),
                  duration_ms = started.elapsed().as_millis() as u64, outcome = "error" }),
        }
        result
        }.instrument(span).await
    }
}

/// Project the final typed identity result, after fallback/reconciliation.
/// Expected authorization, input, admission and conflict outcomes keep their
/// existing events; they are not technical failures of this operation.
fn terminal_identity_failure(error: &ClientError) -> bool {
    match error {
        ClientError::InvalidResponse
        | ClientError::Transport
        | ClientError::Timeout
        | ClientError::CredentialStore
        | ClientError::TelemetryUnavailable => true,
        ClientError::Server(code) => matches!(
            code.as_str(),
            "dependency_unavailable" | "request_timeout" | "revision_exhausted"
        ),
        ClientError::InvalidEndpoint
        | ClientError::InvalidInput
        | ClientError::Cancelled
        | ClientError::Busy
        | ClientError::RevalidationRequired
        | ClientError::Expired
        | ClientError::DeviceRevoked => false,
    }
}

#[cfg(test)]
mod operation_outcome_tests {
    use super::*;

    #[test]
    fn terminal_projection_preserves_expected_identity_outcomes() {
        for error in [
            ClientError::InvalidResponse,
            ClientError::Transport,
            ClientError::Timeout,
            ClientError::CredentialStore,
            ClientError::TelemetryUnavailable,
        ] {
            assert!(terminal_identity_failure(&error));
        }
        for error in [
            ClientError::InvalidEndpoint,
            ClientError::InvalidInput,
            ClientError::Cancelled,
            ClientError::Busy,
            ClientError::RevalidationRequired,
            ClientError::Expired,
            ClientError::DeviceRevoked,
        ] {
            assert!(!terminal_identity_failure(&error));
        }
        for (code, failed) in [
            ("authentication_failed", false),
            ("authorization_denied", false),
            ("challenge_expired", false),
            ("cursor_expired", false),
            ("dependency_unavailable", true),
            ("device_revoked", false),
            ("idempotency_conflict", false),
            ("invalid_request", false),
            ("invalid_signature", false),
            ("method_unavailable", false),
            ("operation_conflict", false),
            ("rate_limited", false),
            ("recent_authentication_required", false),
            ("replayed_nonce", false),
            ("request_timeout", true),
            ("revision_exhausted", true),
            ("server_busy", false),
            ("vault_key_registration_required", false),
        ] {
            let response: wire::Error =
                decode(format!("{{\"error\":\"{code}\"}}").as_bytes()).unwrap();
            let code = serde_json::to_value(response.error).unwrap();
            assert_eq!(
                terminal_identity_failure(&ClientError::Server(code.as_str().unwrap().into())),
                failed
            );
        }
        assert!(matches!(
            decode::<wire::Error>(br#"{"error":"unrecognized_server_error"}"#),
            Err(ClientError::InvalidResponse)
        ));
    }
}

fn clear_flow_state(state: &mut State) {
    state.invitation = None;
    state.flow = None;
    state.view.flow.clear();
    state.view.authorization_url.clear();
    state.view.verification_code.clear();
    state.view.expires_in_seconds = 0;
    state.view.retry_after_seconds = 0;
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ClientError> {
    serde_json::from_slice(body).map_err(|_| ClientError::InvalidResponse)
}
fn passkey_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}
fn valid_token(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn remaining(until: Instant) -> u32 {
    until
        .saturating_duration_since(Instant::now())
        .as_secs()
        .saturating_add(u64::from(until > Instant::now())) as u32
}
fn lifetime(seconds: i32, max: i32) -> Result<Instant, ClientError> {
    if !(1..=max).contains(&seconds) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(Instant::now() + Duration::from_secs(seconds as u64))
}
fn validate_session(session: &wire::Session) -> Result<Instant, ClientError> {
    validate_session_at(session, OffsetDateTime::now_utc(), Instant::now())
}

fn validate_session_at(
    session: &wire::Session,
    wall: OffsetDateTime,
    now: Instant,
) -> Result<Instant, ClientError> {
    if !valid_id(&session.user_id) || !valid_id(&session.tenant_id) || session.expires_at.len() > 40
    {
        return Err(ClientError::InvalidResponse);
    }
    let expires = OffsetDateTime::parse(&session.expires_at, &Rfc3339)
        .map_err(|_| ClientError::InvalidResponse)?;
    let remaining = expires - wall;
    if remaining <= time::Duration::ZERO {
        return Err(ClientError::Expired);
    }
    let maximum = Duration::from_millis(nddev_device_sync_domain::identity::SESSION_LIFETIME_MS);
    // Client and server clocks are independent. Tolerate a small skew at this
    // response sanity boundary, but never extend the canonical local lifetime.
    if remaining.unsigned_abs() > maximum + Duration::from_secs(30) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(now + remaining.unsigned_abs().min(maximum))
}

fn expire_session(state: &mut State, now: Instant, wall_time: OffsetDateTime) {
    if state.view.authenticated
        && (state
            .session_deadline
            .is_some_and(|deadline| deadline <= now)
            || OffsetDateTime::parse(&state.view.expires_at, &Rfc3339)
                .is_ok_and(|expires| expires <= wall_time))
    {
        screen::close_key(state);
        state.view.authenticated = false;
        state.view.session_verified = false;
        state.view.offline_authorized = false;
        state.view.offline_cache_ready = false;
        state.session_deadline = None;
    }
}

pub fn validate_endpoint(input: &str) -> Result<Url, ClientError> {
    if input.len() > 2048 {
        return Err(ClientError::InvalidEndpoint);
    }
    let url = Url::parse(input).map_err(|_| ClientError::InvalidEndpoint)?;
    let loopback = matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback())
        || url.host_str() == Some("localhost");
    let scheme_allowed = url.scheme() == "https"
        || (cfg!(feature = "development-http")
            && cfg!(debug_assertions)
            && url.scheme() == "http"
            && loopback);
    if !scheme_allowed
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ClientError::InvalidEndpoint);
    }
    Ok(url)
}

pub fn validate_github_url(input: &str, endpoint: &Url) -> Result<(), ClientError> {
    let url = Url::parse(input).map_err(|_| ClientError::InvalidResponse)?;
    if input.len() > 2048
        || url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.path() != "/login/oauth/authorize"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|p| p != 443)
    {
        return Err(ClientError::InvalidResponse);
    }
    let mut query = std::collections::BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if query.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err(ClientError::InvalidResponse);
        }
    }
    let keys = [
        "allow_signup",
        "client_id",
        "code_challenge",
        "code_challenge_method",
        "redirect_uri",
        "scope",
        "state",
    ];
    if query.keys().map(String::as_str).ne(keys) {
        return Err(ClientError::InvalidResponse);
    }
    let client_id = &query["client_id"];
    if client_id.is_empty()
        || client_id.len() > 128
        || !client_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        || query["scope"] != "read:user"
        || query["code_challenge_method"] != "S256"
        || query["allow_signup"] != "false"
        || ["state", "code_challenge"]
            .iter()
            .any(|key| query[*key].len() != 43 || !valid_token(&query[*key]))
    {
        return Err(ClientError::InvalidResponse);
    }
    let callback = Url::parse(&query["redirect_uri"]).map_err(|_| ClientError::InvalidResponse)?;
    if callback.scheme() != "https"
        || callback.origin() != endpoint.origin()
        || callback.path() != "/v2/auth/github/callback"
        || callback.query().is_some()
        || callback.fragment().is_some()
        || !callback.username().is_empty()
        || callback.password().is_some()
    {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod native_completion_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires an actual unlocked native store; owns one fresh entry"]
    async fn cancellation_after_native_persistence_requires_revalidation() {
        let endpoint = format!("https://nds-completion-{}.invalid", uuid::Uuid::new_v4());
        let client = IdentityClient::new(&endpoint).unwrap();
        let (_permit, cancel) = client.operation().await.unwrap();
        assert!(client.store.read().await.unwrap().is_none());
        let secret = uuid::Uuid::new_v4().simple().to_string().repeat(2);
        client.store.write(secret.as_bytes()).await.unwrap();
        client.cancel();
        let result = client.finish_persisted_session(
            wire::Session {
                user_id: "ephemeral-owner".into(),
                tenant_id: "ephemeral-tenant".into(),
                auth_method: wire::AuthMethod::EmailOtp,
                expires_at: (OffsetDateTime::now_utc() + time::Duration::hours(1))
                    .format(&Rfc3339)
                    .unwrap(),
            },
            Instant::now() + Duration::from_secs(3600),
            &cancel,
            false,
        );
        let view = client.view();
        let persisted = client.store.read().await;
        client.store.delete().await.unwrap();
        assert_eq!(result, Err(ClientError::RevalidationRequired));
        assert!(
            !view.authenticated && !view.session_verified && view.credential_revalidation_required
        );
        assert!(persisted.unwrap().is_some());
    }

    #[test]
    fn cancelled_response_cannot_recreate_a_sign_in_flow() {
        let client = IdentityClient::new("https://cancelled.example").unwrap();
        let cancel = CancellationToken::new();
        *client.cancellation.lock().unwrap() = cancel.clone();
        client.cancel_sign_in();
        let result = client.finish_flow(
            Flow::Email {
                id: "ephemeral-flow".into(),
                expires: Instant::now() + Duration::from_secs(30),
                resend: Instant::now(),
            },
            String::new(),
            String::new(),
            &cancel,
        );
        assert_eq!(result, Err(ClientError::Cancelled));
        assert!(client.view().flow.is_empty());
    }

    #[test]
    fn expired_flow_is_removed_from_owned_state_and_view() {
        let client = IdentityClient::new("https://expired.example").unwrap();
        let cancel = CancellationToken::new();
        *client.cancellation.lock().unwrap() = cancel.clone();
        client
            .finish_flow(
                Flow::Browser {
                    passkey: false,
                    registration: false,
                    id: "ephemeral-flow".into(),
                    token: Zeroizing::new("ephemeral-token".into()),
                    expires: Instant::now(),
                    next_poll: Instant::now(),
                },
                "ephemeral-url".into(),
                "12345678".into(),
                &cancel,
            )
            .unwrap();
        let view = client.view();
        assert!(
            view.flow.is_empty()
                && view.authorization_url.is_empty()
                && view.verification_code.is_empty()
        );
        assert!(client.state.lock().unwrap().flow.is_none());
    }

    #[test]
    fn view_debug_never_contains_authorization_query_or_identity() {
        let view = View {
            authorization_url: "sensitive-authorization-url".into(),
            verification_code: "12345678".into(),
            user_id: "sensitive-user-id".into(),
            ..View::default()
        };
        let output = format!("{view:?}");
        assert!(!output.contains("sensitive") && !output.contains("12345678"));
    }

    #[test]
    fn expired_state_cannot_revive_when_wall_clock_moves_back() {
        let now = Instant::now();
        let wall = OffsetDateTime::now_utc();
        let mut state = State::default();
        state.view.authenticated = true;
        state.view.session_verified = true;
        state.view.expires_at = (wall + time::Duration::seconds(60))
            .format(&Rfc3339)
            .unwrap();
        state.session_deadline = Some(now + Duration::from_secs(60));
        expire_session(
            &mut state,
            now + Duration::from_secs(1),
            wall + time::Duration::seconds(61),
        );
        assert!(!state.view.authenticated);
        expire_session(
            &mut state,
            now + Duration::from_secs(2),
            wall - time::Duration::hours(1),
        );
        assert!(!state.view.authenticated && !state.view.session_verified);
    }

    #[test]
    fn small_clock_skew_is_tolerated_without_extending_session_lifetime() {
        let now = Instant::now();
        let wall = OffsetDateTime::UNIX_EPOCH;
        let maximum =
            Duration::from_millis(nddev_device_sync_domain::identity::SESSION_LIFETIME_MS);
        for (skew, accepted) in [(1, true), (30, true), (31, false)] {
            let session = wire::Session {
                user_id: "owner".into(),
                tenant_id: "tenant".into(),
                auth_method: wire::AuthMethod::EmailOtp,
                expires_at: (wall + maximum + time::Duration::seconds(skew))
                    .format(&Rfc3339)
                    .unwrap(),
            };
            let result = validate_session_at(&session, wall, now);
            if accepted {
                assert_eq!(result.unwrap(), now + maximum);
            } else {
                assert_eq!(result, Err(ClientError::InvalidResponse));
            }
        }
    }

    #[test]
    fn remote_session_cannot_exceed_the_core_lifetime_contract() {
        let session = wire::Session {
            user_id: "owner".into(),
            tenant_id: "tenant".into(),
            auth_method: wire::AuthMethod::EmailOtp,
            expires_at: (OffsetDateTime::now_utc() + time::Duration::hours(9))
                .format(&Rfc3339)
                .unwrap(),
        };
        assert_eq!(
            validate_session(&session),
            Err(ClientError::InvalidResponse)
        );
    }
}

/// Identity selection is distinct from authentication. Registration has no
/// selector: its owner comes exclusively from the verified current session.
fn passkey_request(
    registration: bool,
    email: Option<String>,
) -> Result<wire::PasskeyRequest, ClientError> {
    if registration && email.is_some() {
        return Err(ClientError::InvalidInput);
    }
    let email = email
        .map(|value| {
            nddev_device_sync_domain::identity::EmailAddress::parse(&value)
                .map(|email| email.as_str().to_owned())
                .map_err(|_| ClientError::InvalidInput)
        })
        .transpose()?;
    Ok(wire::PasskeyRequest {
        registration,
        email,
    })
}

#[cfg(test)]
mod passkey_selector_tests {
    use super::*;
    #[test]
    fn generated_request_carries_canonical_selector_only_for_login() {
        let value = passkey_request(false, Some(" Member@Example.Invalid ".into())).unwrap();
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            serde_json::json!({"registration":false,"email":"member@example.invalid"})
        );
        assert_eq!(
            serde_json::to_value(passkey_request(true, None).unwrap()).unwrap(),
            serde_json::json!({"registration":true})
        );
        // The server alone can resolve an omitted selector to one active account.
        assert_eq!(
            serde_json::to_value(passkey_request(false, None).unwrap()).unwrap(),
            serde_json::json!({"registration":false})
        );
        for value in [
            "",
            "not-email",
            "person@example.invalid\nother@example.invalid",
        ] {
            assert!(passkey_request(false, Some(value.into())).is_err());
        }
        assert!(passkey_request(true, Some("other@example.invalid".into())).is_err());
    }
}
