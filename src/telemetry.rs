//! Authenticated native delivery shared by Flutter and the agent CLI. The SDK
//! owns record/batch lifetime; this adapter owns policy, bounded retries and I/O.
use crate::runtime::{self, Instant, Task};
use crate::{ClientError, IdentityClient, SyncRequest, observability_wire as wire};
use nddev_device_sync_telemetry::ExportFeed;
mod receipt;
mod source;
use source::{Batch, Source};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub use crate::view::{DeliveryView, ExportPolicy};
pub struct Delivery {
    source: Arc<Source>,
    state: Arc<Mutex<DeliveryView>>,
    active: watch::Sender<bool>,
    cancel: CancellationToken,
    task: Task,
}
impl Delivery {
    pub fn start(
        identity: Arc<IdentityClient>,
        events: ExportFeed,
        traces: ExportFeed,
        foreground: bool,
    ) -> Self {
        let source = Arc::new(Source::new(&identity, events, traces));
        let state = Arc::new(Mutex::new(DeliveryView {
            initialized: true,
            paused: !foreground,
            ..Default::default()
        }));
        let (active, receiver) = watch::channel(foreground);
        let cancel = CancellationToken::new();
        #[cfg(target_arch = "wasm32")]
        source.start_staging(cancel.clone());
        let task = runtime::spawn(run(
            identity,
            source.clone(),
            state.clone(),
            receiver,
            cancel.clone(),
        ));
        Self {
            source,
            state,
            active,
            cancel,
            task,
        }
    }
    pub fn snapshot(&self) -> DeliveryView {
        let mut view = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        self.source.snapshot(&mut view);
        view
    }
    pub fn foreground(&self, active: bool) {
        self.active.send_replace(active);
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .paused = !active;
    }
    pub fn finished(&self) -> bool {
        self.task.is_finished()
    }
    /// Try to drain while the process is still running. Returns truthful counters
    /// after at most five seconds; Drop accounts for any remaining records.
    pub async fn flush(&self) -> DeliveryView {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let view = self.snapshot();
            if view.pending + view.spans_pending == 0
                || !view.initialized
                || view.paused
                || Instant::now() >= deadline
            {
                return view;
            }
            runtime::sleep(Duration::from_millis(50)).await;
        }
    }
}
impl Drop for Delivery {
    fn drop(&mut self) {
        self.source.close();
        self.cancel.cancel();
        self.task.abort();
    }
}
struct Worker {
    source: Arc<Source>,
    state: Arc<Mutex<DeliveryView>>,
    cancel: CancellationToken,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.source.close();
        self.cancel.cancel();
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .initialized = false;
    }
}
fn record_failure(state: &Mutex<DeliveryView>) {
    let mut view = state.lock().unwrap_or_else(|error| error.into_inner());
    view.failures = view.failures.saturating_add(1);
}
fn terminal(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::DeviceRevoked | ClientError::RevalidationRequired | ClientError::Cancelled
    ) || matches!(error, ClientError::Server(code) if code == "authentication_failed" || code == "device_revoked")
}
async fn run(
    identity: Arc<IdentityClient>,
    source: Arc<Source>,
    state: Arc<Mutex<DeliveryView>>,
    mut active: watch::Receiver<bool>,
    cancel: CancellationToken,
) {
    let _worker = Worker {
        source: source.clone(),
        state: state.clone(),
        cancel: cancel.clone(),
    };
    let mut pending: Option<Batch> = None;
    let mut attempts = 0u32;
    let mut delay = Duration::ZERO;
    let mut checked: Option<Instant> = None;
    let mut trace_turn = false;
    loop {
        // Scope loss ends this delivery owner before starting another local ACK.
        // An SDK operation already admitted still owns its atomic completion.
        if !source.matches(&identity) {
            break;
        }
        // A known receipt owns this batch until local settlement. It never
        // re-enters policy discovery, parking, selection or network delivery.
        if pending.as_ref().is_some_and(Batch::received) {
            let batch = pending.as_mut().expect("owned receipted export batch");
            #[cfg(not(target_arch = "wasm32"))]
            let full = batch.full_receipt();
            // One attempt may finish on the original owned tail after payload
            // expiry. This does not renew the lease or extend batch retention.
            let settled = tokio::select! {
                _=cancel.cancelled()=>break,
                result=batch.acknowledge(&source)=>result,
            };
            if settled.is_err() {
                record_failure(&state);
                if batch.expired() {
                    break;
                }
                // Local retry keeps the same known receipt. SDK11 renews only
                // the existing owned sender lease, never the batch retention.
                tokio::select! { _=cancel.cancelled()=>break, _=runtime::sleep(Duration::from_secs(5))=>{} }
                continue;
            }
            trace_turn = !batch.trace();
            pending = None;
            #[cfg(not(target_arch = "wasm32"))]
            if full {
                state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last_success_at = time::OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .try_into()
                    .unwrap_or_default();
            }
            delay = Duration::from_millis(200);
            continue;
        }
        if pending.as_ref().is_some_and(Batch::expired)
            && let Some(batch) = pending.take()
        {
            let _ = batch.discard(&source).await;
        }
        // Opportunistic expiry also runs while backgrounded; never send a
        // retained batch merely because policy discovery was unavailable.
        if source.maintain().await.is_err() {
            Batch::park(&mut pending);
            record_failure(&state);
            tokio::select! { _ = cancel.cancelled() => break, _ = runtime::sleep(Duration::from_secs(5)) => {} }
            continue;
        }
        if !*active.borrow() {
            Batch::park(&mut pending);
            tokio::select! { _ = cancel.cancelled() => break, changed = active.changed() => { if changed.is_err() { break; } }, _ = runtime::sleep(Duration::from_secs(30)) => {} }
            checked = None;
            delay = Duration::ZERO;
            continue;
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = active.changed() => { if changed.is_err() { break; } Batch::park(&mut pending); checked = None; delay = Duration::ZERO; continue; },
            _ = runtime::sleep(delay) => {}
        }
        if checked.is_none_or(|time| time.elapsed() >= Duration::from_secs(30)) {
            let result = tokio::select! {
                _ = cancel.cancelled() => break,
                changed = active.changed() => { if changed.is_err() { break; } Batch::park(&mut pending); checked = None; continue; },
                result = identity.sync_request(SyncRequest::TelemetryPolicy) => result,
            }.and_then(|reply| serde_json::from_slice::<wire::ClientTelemetryPolicy>(&reply.body).map_err(|_| ClientError::InvalidResponse));
            match result {
                Ok(status) => {
                    let enabled = matches!(status.export_mode, wire::ExportMode::Enabled);
                    if source.set_enabled(enabled).await.is_err() {
                        record_failure(&state);
                        delay = Duration::from_secs(5);
                        continue;
                    }
                    state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .policy = if enabled {
                        ExportPolicy::Enabled
                    } else {
                        ExportPolicy::Disabled
                    };
                    if !enabled {
                        pending = None;
                    }
                    checked = Some(Instant::now());
                }
                Err(error) if terminal(&error) => break,
                Err(ClientError::Busy) => {
                    delay = Duration::from_secs(1);
                    continue;
                }
                Err(_) => {
                    let mut view = state.lock().unwrap_or_else(|error| error.into_inner());
                    view.policy = ExportPolicy::Unknown;
                    view.failures = view.failures.saturating_add(1);
                    delay = Duration::from_secs(5);
                    continue;
                }
            }
        }
        if state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .policy
            != ExportPolicy::Enabled
        {
            delay = Duration::from_secs(2);
            continue;
        }
        if pending.is_none() {
            pending = match source.next(trace_turn).await {
                Ok(batch) => batch,
                Err(()) => {
                    record_failure(&state);
                    delay = Duration::from_secs(1);
                    continue;
                }
            };
            attempts = pending.as_ref().map_or(0, Batch::attempts);
        }
        let Some(batch) = &pending else {
            delay = Duration::from_secs(2);
            continue;
        };
        if batch.expired() || attempts >= 8 {
            if let Some(batch) = pending.take() {
                let _ = batch.discard(&source).await;
            }
            delay = Duration::ZERO;
            continue;
        }
        let request = if batch.trace() {
            SyncRequest::NativeTraces(batch.bytes().to_vec())
        } else {
            SyncRequest::Telemetry(batch.bytes().to_vec())
        };
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            changed = active.changed() => { if changed.is_err() { break; } Batch::park(&mut pending); checked = None; continue; },
            result = identity.sync_request(request) => result,
        }.and_then(|reply| serde_json::from_slice::<wire::IngressReceipt>(&reply.body).map_err(|_| ClientError::InvalidResponse));
        match result {
            Ok(receipt) if matches!(receipt.export_mode, wire::ExportMode::Disabled) => {
                if source.set_enabled(false).await.is_err() {
                    record_failure(&state);
                }
                pending = None;
                state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .policy = ExportPolicy::Disabled;
                checked = Some(Instant::now());
                delay = Duration::from_secs(2);
            }
            Ok(receipt)
                if receipt::accepted_count(batch.trace(), batch.count(), &receipt).is_some() =>
            {
                let batch = pending.as_mut().expect("owned export batch");
                assert!(batch.receive(&receipt));
                delay = Duration::ZERO;
            }
            Err(error) if terminal(&error) => break,
            Err(ClientError::Busy) => {
                Batch::park(&mut pending);
                delay = Duration::from_secs(1);
            }
            _ => {
                if batch.failed(&source).await.is_err() {
                    record_failure(&state);
                    pending = None;
                    checked = None;
                    delay = Duration::from_secs(5);
                    continue;
                }
                attempts += 1;
                Batch::park(&mut pending);
                delay = Duration::from_secs(1 << attempts.min(5));
            }
        }
    }
}

#[cfg(all(test, feature = "development-http"))]
mod acceptance;
