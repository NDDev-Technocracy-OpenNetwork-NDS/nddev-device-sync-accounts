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

pub use crate::view::{DeliveryCollection, DeliveryView, ExportPolicy};

/// One validated effective policy: its mode and, for debug, the unix second it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Effective {
    pub mode: DeliveryCollection,
    pub debug_expires_at: u64,
}
/// Validates a stated collection policy: debug always carries a future end, other modes none.
pub(crate) fn effective(
    policy: &wire::CollectionPolicy,
    now: u64,
) -> Result<Effective, ClientError> {
    let expires = policy
        .debug_expires_at
        .as_deref()
        .map(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .ok()
                .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
                .ok_or(ClientError::InvalidResponse)
        })
        .transpose()?;
    match (&policy.mode, expires) {
        (wire::CollectionMode::Standard, None) => Ok(Effective {
            mode: DeliveryCollection::Standard,
            debug_expires_at: 0,
        }),
        (wire::CollectionMode::Off, None) => Ok(Effective {
            mode: DeliveryCollection::Off,
            debug_expires_at: 0,
        }),
        // An expired window is standard: debug never outlives its stated end.
        (wire::CollectionMode::Debug, Some(end)) if end <= now => Ok(Effective {
            mode: DeliveryCollection::Standard,
            debug_expires_at: 0,
        }),
        (wire::CollectionMode::Debug, Some(end)) => Ok(Effective {
            mode: DeliveryCollection::Debug,
            debug_expires_at: end,
        }),
        _ => Err(ClientError::InvalidResponse),
    }
}
/// The effective policy from the server. An older server without the collection route answers
/// with the export-only client policy, read as standard (enabled) or off (disabled).
async fn discover(identity: &IdentityClient) -> Result<Effective, ClientError> {
    let now = time::OffsetDateTime::now_utc()
        .unix_timestamp()
        .try_into()
        .unwrap_or_default();
    match identity.sync_request(SyncRequest::CollectionPolicy).await {
        Ok(reply) => serde_json::from_slice::<wire::CollectionPolicy>(&reply.body)
            .map_err(|_| ClientError::InvalidResponse)
            .and_then(|policy| effective(&policy, now)),
        Err(ClientError::Server(code)) if code == "collection_policy_unavailable" => {
            let reply = identity.sync_request(SyncRequest::TelemetryPolicy).await?;
            let legacy = serde_json::from_slice::<wire::ClientTelemetryPolicy>(&reply.body)
                .map_err(|_| ClientError::InvalidResponse)?;
            Ok(Effective {
                mode: if matches!(legacy.export_mode, wire::ExportMode::Enabled) {
                    DeliveryCollection::Standard
                } else {
                    DeliveryCollection::Off
                },
                debug_expires_at: 0,
            })
        }
        Err(error) => Err(error),
    }
}
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
fn admission_delayed(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Busy | ClientError::OnlineVerificationRequired
    ) || matches!(error, ClientError::Server(code) if code == "server_busy")
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
            // A receipt releases the next bounded batch immediately. Sparse
            // ingress can create small batches; a success delay would cap their
            // throughput below ordinary background events even with healthy I/O.
            delay = Duration::ZERO;
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
                result = discover(&identity) => result,
            };
            match result {
                Ok(policy) => {
                    // Off collects and exports nothing new and keeps no hidden stream.
                    let enabled = policy.mode != DeliveryCollection::Off;
                    if source.set_enabled(enabled).await.is_err() {
                        record_failure(&state);
                        delay = Duration::from_secs(5);
                        continue;
                    }
                    {
                        let mut view = state.lock().unwrap_or_else(|error| error.into_inner());
                        view.policy = if enabled {
                            ExportPolicy::Enabled
                        } else {
                            ExportPolicy::Disabled
                        };
                        view.collection = policy.mode;
                        view.debug_expires_at = policy.debug_expires_at;
                    }
                    if !enabled {
                        pending = None;
                    }
                    checked = Some(Instant::now());
                }
                Err(error) if terminal(&error) => break,
                Err(error) if admission_delayed(&error) => {
                    delay = Duration::from_secs(1);
                    continue;
                }
                Err(_) => {
                    let mut view = state.lock().unwrap_or_else(|error| error.into_inner());
                    view.policy = ExportPolicy::Unknown;
                    view.collection = DeliveryCollection::Unknown;
                    view.debug_expires_at = 0;
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
            Err(error) if admission_delayed(&error) => {
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

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn policy(mode: wire::CollectionMode, expires: Option<&str>) -> wire::CollectionPolicy {
        wire::CollectionPolicy {
            mode,
            debug_expires_at: expires.map(str::to_owned),
            revision: 1,
        }
    }

    #[test]
    fn debug_is_finite_and_every_other_mode_carries_no_expiry() {
        let now = 1_793_500_000; // 2026-11-01T02:26:40Z
        assert_eq!(
            effective(
                &policy(wire::CollectionMode::Debug, Some("2026-11-01T06:00:00Z")),
                now
            ),
            Ok(Effective {
                mode: DeliveryCollection::Debug,
                debug_expires_at: 1_793_512_800
            })
        );
        // A window that already ended is standard; debug never outlives its end.
        assert_eq!(
            effective(
                &policy(wire::CollectionMode::Debug, Some("2026-11-01T00:00:00Z")),
                now
            )
            .map(|e| e.mode),
            Ok(DeliveryCollection::Standard)
        );
        assert_eq!(
            effective(&policy(wire::CollectionMode::Off, None), now).map(|e| e.mode),
            Ok(DeliveryCollection::Off)
        );
        assert_eq!(
            effective(&policy(wire::CollectionMode::Standard, None), now).map(|e| e.mode),
            Ok(DeliveryCollection::Standard)
        );
        // Contradictory statements are refused, never guessed.
        for (mode, expires) in [
            (wire::CollectionMode::Debug, None),
            (wire::CollectionMode::Standard, Some("2026-11-01T06:00:00Z")),
            (wire::CollectionMode::Off, Some("2026-11-01T06:00:00Z")),
            (wire::CollectionMode::Debug, Some("tomorrow")),
        ] {
            assert!(effective(&policy(mode, expires), now).is_err());
        }
    }
}
