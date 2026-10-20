//! Browser-managed wrapping key and encrypted credential adapter. Its secret
//! bytes terminate in Rust, never in presentation DTOs or the replica database.
use super::*;
use futures::{FutureExt, channel::oneshot, future::Either};
use js_sys::Uint8Array;
use tracing::Instrument;
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(module = "/src/browser_credentials.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name=clearOfflineAccess)]
    fn clear_access() -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch, js_name = credentialOperation)]
    fn credential_operation(
        action: &str,
        service: &str,
        key: &str,
        value: &[u8],
    ) -> Result<js_sys::Promise, JsValue>;
}

pub(super) fn failure(value: JsValue) -> ClientError {
    if value
        .dyn_ref::<js_sys::Error>()
        .is_some_and(|e| e.message() == "credential_store_busy")
    {
        ClientError::Busy
    } else {
        ClientError::CredentialStore
    }
}

impl SessionStore {
    pub(super) async fn browser_io<T: 'static>(
        &self,
        event: &'static str,
        operation: impl std::future::Future<Output = Result<T, ClientError>> + 'static,
    ) -> Result<T, ClientError> {
        let span = io_span(event)?;
        let (permit, remaining) = self.admit_io(&span).await?;
        let owner = self.owner.clone();
        let lease = owner
            .lease
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade();
        let (sender, receiver) = oneshot::channel();
        // As with the native OS adapter, cancellation of the waiting caller
        // cannot release admission while an uninterruptible credential write
        // still owns its transaction. A late completion remains observable.
        wasm_bindgen_futures::spawn_local(
            async move {
                let _permit = permit;
                let _owner = owner;
                let _lease = lease;
                let started = web_time::Instant::now();
                let result = operation.await;
                report_io(event, &result, started.elapsed().as_millis() as u64);
                let _ = sender.send(result);
            }
            .instrument(span.clone()),
        );
        match futures::future::select(
            receiver.boxed_local(),
            gloo_timers::future::TimeoutFuture::new(remaining.as_millis() as u32).boxed_local(),
        )
        .await
        {
            Either::Left((Ok(value), _)) => value,
            Either::Left((Err(_), _)) => Err(ClientError::CredentialStore),
            Either::Right(_) => {
                span.in_scope(|| tracing::event!(target:"nds_accounts",tracing::Level::WARN, { event.name="identity.credential.wait_failed", module="accounts", scope="io", error.type="request_timeout", outcome="error"}));
                Err(ClientError::Timeout)
            }
        }
    }

    async fn browser_operation(
        &self,
        action: &'static str,
        event: &'static str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError> {
        if value.len() > 65_536 {
            return Err(ClientError::InvalidInput);
        }
        let service = self.service;
        let key = self.key.clone();
        self.browser_io(event, async move {
            let promise = credential_operation(action, service, &key, &value).map_err(failure)?;
            let value = JsFuture::from(promise).await.map_err(failure)?;
            if value.is_null() {
                return Ok(None);
            }
            let value = value.dyn_into::<Uint8Array>().map_err(failure)?;
            if value.length() > 65_536 {
                value.fill(0, 0, value.length());
                return Err(ClientError::CredentialStore);
            }
            let secret = Zeroizing::new(value.to_vec());
            value.fill(0, 0, value.length());
            Ok(Some(secret))
        })
        .await
    }

    pub(crate) async fn clear_browser_access(&self) -> Result<(), ClientError> {
        self.browser_io("identity.offline.access_cleared", async {
            let promise = clear_access().map_err(failure)?;
            JsFuture::from(promise).await.map_err(failure)?;
            Ok(())
        })
        .await
    }

    pub async fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError> {
        self.browser_operation(
            "read",
            "identity.credential.read",
            Zeroizing::new(Vec::new()),
        )
        .await
    }

    pub async fn write(&self, value: &[u8]) -> Result<(), ClientError> {
        self.browser_operation(
            "write",
            "identity.credential.write",
            Zeroizing::new(value.to_vec()),
        )
        .await
        .map(|_| ())
    }

    pub async fn delete(&self) -> Result<(), ClientError> {
        self.browser_operation(
            "delete",
            "identity.credential.delete",
            Zeroizing::new(Vec::new()),
        )
        .await
        .map(|_| ())
    }
}
