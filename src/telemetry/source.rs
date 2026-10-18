//! The sender has one delivery policy. Its actual queue adapters differ: native
//! owns bounded RAM batches; browser owns durable SDK batches plus a RAM ingress.
use crate::{IdentityClient, view::DeliveryView};
#[cfg(not(target_arch = "wasm32"))]
use nddev_device_sync_telemetry::ExportBatch;
use nddev_device_sync_telemetry::ExportFeed;
#[cfg(target_arch = "wasm32")]
use nddev_device_sync_telemetry::FeedHealth;
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use {
    nddev_device_sync_telemetry::browser_queue::{self, Signal},
    std::sync::Mutex,
};

const MAX_COUNTER: u64 = 9_007_199_254_740_991;
fn add(a: u64, b: u64) -> u64 {
    a.saturating_add(b).min(MAX_COUNTER)
}
fn scope(identity: &IdentityClient) -> String {
    let view = identity.view();
    let mut hash = Sha256::new();
    for value in [
        identity.origin(),
        view.tenant_id,
        view.user_id,
        view.current_device_id,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    base16ct::lower::encode_string(&hash.finalize())
}
#[cfg(target_arch = "wasm32")]
#[derive(Default)]
struct Persistent {
    disk: Option<browser_queue::Health>,
    ready: bool,
    observed: bool,
    events_reported: FeedHealth,
    traces_reported: FeedHealth,
}
pub(super) struct Source {
    pub events: Arc<ExportFeed>,
    pub traces: Arc<ExportFeed>,
    scope: String,
    #[cfg(target_arch = "wasm32")]
    queue: browser_queue::Queue,
    #[cfg(target_arch = "wasm32")]
    persistent: Mutex<Persistent>,
}
impl Source {
    pub fn new(identity: &IdentityClient, events: ExportFeed, traces: ExportFeed) -> Self {
        let scope = scope(identity);
        Self {
            events: Arc::new(events),
            traces: Arc::new(traces),
            #[cfg(target_arch = "wasm32")]
            queue: browser_queue::Queue::new(scope.clone()).expect("SHA-256 delivery scope"),
            scope,
            #[cfg(target_arch = "wasm32")]
            persistent: Mutex::default(),
        }
    }
    pub fn matches(&self, identity: &IdentityClient) -> bool {
        let view = identity.view();
        view.authenticated
            && !view.current_device_id.is_empty()
            && view.devices.iter().any(|d| d.is_current && !d.revoked)
            && self.scope == scope(identity)
    }
    pub fn close(&self) {
        self.events.close();
        self.traces.close();
    }
    pub fn snapshot(&self, view: &mut DeliveryView) {
        let events = self.events.health();
        let traces = self.traces.health();
        view.pending = events.pending;
        view.delivered = events.delivered;
        view.dropped = events.dropped;
        view.failures = add(view.failures, events.failures);
        view.spans_pending = traces.pending;
        view.spans_delivered = traces.delivered;
        view.spans_dropped = traces.dropped;
        view.spans_failures = traces.failures;
        #[cfg(target_arch = "wasm32")]
        {
            let stored = self.persistent.lock().unwrap_or_else(|e| e.into_inner());
            view.local_persistence_ready = Some(stored.ready);
            if let Some(disk) = &stored.disk {
                view.pending += disk.events.pending;
                view.spans_pending += disk.traces.pending;
                view.delivered = add(view.delivered, disk.events.delivered);
                view.spans_delivered = add(view.spans_delivered, disk.traces.delivered);
                view.dropped = add(
                    events
                        .dropped
                        .saturating_sub(stored.events_reported.dropped),
                    disk.events.dropped,
                );
                view.spans_dropped = add(
                    traces
                        .dropped
                        .saturating_sub(stored.traces_reported.dropped),
                    disk.traces.dropped,
                );
                view.failures = add(
                    view.failures
                        .saturating_sub(stored.events_reported.failures),
                    disk.events.failures,
                );
                view.spans_failures = add(
                    traces
                        .failures
                        .saturating_sub(stored.traces_reported.failures),
                    disk.traces.failures,
                );
                view.last_success_at = disk.last_success_at;
            }
        }
    }
    #[cfg(target_arch = "wasm32")]
    fn remember(
        &self,
        result: Result<browser_queue::Health, nddev_device_sync_telemetry::Error>,
        write_confirmed: bool,
    ) -> Result<(), ()> {
        let mut stored = self.persistent.lock().unwrap_or_else(|e| e.into_inner());
        let mut transition = None;
        let result = match result {
            Ok(health) => {
                if stored
                    .disk
                    .as_ref()
                    .is_none_or(|old| old.revision <= health.revision)
                {
                    stored.disk = Some(health);
                }
                // A successful read or a small counter update cannot establish
                // recovery after a failed payload write (for example quota).
                if write_confirmed {
                    if !stored.observed || !stored.ready {
                        transition = Some(true);
                    }
                    stored.ready = true;
                    stored.observed = true;
                }
                Ok(())
            }
            Err(_) => {
                if !stored.observed || stored.ready {
                    transition = Some(false);
                }
                stored.ready = false;
                stored.observed = true;
                Err(())
            }
        };
        drop(stored);
        if let Some(ready) = transition {
            nddev_device_sync_telemetry::delivery_span().in_scope(|| {
                if ready {
                    tracing::event!(target:"nds_accounts",tracing::Level::INFO,{event.name="telemetry.spool.ready",module="accounts",scope="io",outcome="ready"});
                } else {
                    tracing::event!(target:"nds_accounts",tracing::Level::WARN,{event.name="telemetry.spool.unavailable",module="accounts",scope="io",error.type="telemetry_store_unavailable",outcome="error"});
                }
            });
        }
        result
    }
    pub async fn maintain(&self) -> Result<(), ()> {
        self.events.health();
        self.traces.health();
        #[cfg(target_arch = "wasm32")]
        self.remember(self.queue.health().await, false)?;
        Ok(())
    }
    pub async fn set_enabled(&self, enabled: bool) -> Result<(), ()> {
        if !enabled {
            self.events.set_enabled(false);
            self.traces.set_enabled(false);
        }
        #[cfg(target_arch = "wasm32")]
        self.remember(self.queue.set_enabled(enabled).await, false)?;
        if enabled {
            self.events.set_enabled(true);
            self.traces.set_enabled(true);
        }
        Ok(())
    }
    pub async fn next(&self, prefer_trace: bool) -> Result<Option<Batch>, ()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let selected = if prefer_trace {
                self.traces
                    .take_batch()
                    .map(|b| (b, true))
                    .or_else(|| self.events.take_batch().map(|b| (b, false)))
            } else {
                self.events
                    .take_batch()
                    .map(|b| (b, false))
                    .or_else(|| self.traces.take_batch().map(|b| (b, true)))
            };
            Ok(selected.map(|(batch, trace)| Batch {
                batch,
                trace,
                accepted: None,
            }))
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = prefer_trace;
            let sender = match self.queue.sender().await {
                Ok(Some(sender)) => sender,
                Ok(None) => return Ok(None),
                Err(error) => {
                    let _ = self.remember(Err(error), false);
                    return Err(());
                }
            };
            let batch = match sender.next().await {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = self.remember(Err(error), false);
                    return Err(());
                }
            };
            Ok(batch.map(|batch| Batch {
                batch,
                sender,
                accepted: None,
            }))
        }
    }
    #[cfg(target_arch = "wasm32")]
    pub fn start_staging(self: &Arc<Self>, cancel: tokio_util::sync::CancellationToken) {
        let source = self.clone();
        crate::runtime::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                let mut work = false;
                for (feed, signal) in [
                    (&source.events, Signal::Events),
                    (&source.traces, Signal::Traces),
                ] {
                    if cancel.is_cancelled() {
                        break;
                    }
                    if let Some(batch) = feed.take_batch() {
                        work = true;
                        let result = source.queue.persist(signal, batch).await;
                        if result.as_ref().is_ok_and(|h| !h.enabled) {
                            source.events.set_enabled(false);
                            source.traces.set_enabled(false);
                        }
                        let _ = source.remember(result, true);
                    }
                }
                let _ = source.report_losses().await;
                if !work {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = source.events.ready() => {},
                        _ = source.traces.ready() => {},
                        _ = crate::runtime::sleep(std::time::Duration::from_millis(200)) => {},
                    }
                }
            }
            // Closing RAM capture can account for previously unstaged records.
            // Finish this one bounded write; Drop never aborts committed I/O.
            let _ = source.report_losses().await;
        });
    }
    #[cfg(target_arch = "wasm32")]
    async fn report_losses(&self) -> Result<(), ()> {
        let events = self.events.health();
        let traces = self.traces.health();
        let (a, b) = {
            let s = self.persistent.lock().unwrap_or_else(|e| e.into_inner());
            (
                FeedHealth {
                    dropped: events.dropped.saturating_sub(s.events_reported.dropped),
                    failures: events.failures.saturating_sub(s.events_reported.failures),
                    ..Default::default()
                },
                FeedHealth {
                    dropped: traces.dropped.saturating_sub(s.traces_reported.dropped),
                    failures: traces.failures.saturating_sub(s.traces_reported.failures),
                    ..Default::default()
                },
            )
        };
        if a.dropped + a.failures + b.dropped + b.failures == 0 {
            return Ok(());
        }
        let health = self.queue.record_losses(a, b).await.map_err(|_| ())?;
        let mut stored = self.persistent.lock().unwrap_or_else(|e| e.into_inner());
        if stored
            .disk
            .as_ref()
            .is_none_or(|old| old.revision <= health.revision)
        {
            stored.disk = Some(health);
        }
        stored.events_reported = events;
        stored.traces_reported = traces;
        Ok(())
    }
}
pub(super) struct Batch {
    accepted: Option<i64>,
    #[cfg(not(target_arch = "wasm32"))]
    batch: ExportBatch,
    #[cfg(not(target_arch = "wasm32"))]
    trace: bool,
    #[cfg(target_arch = "wasm32")]
    batch: browser_queue::Batch,
    #[cfg(target_arch = "wasm32")]
    sender: browser_queue::Sender,
}
impl Batch {
    /// Unknown browser batches can be reselected after retry/pause. A known
    /// receipt retains its exact batch and sender for local settlement only.
    pub fn park(pending: &mut Option<Self>) {
        #[cfg(target_arch = "wasm32")]
        {
            if pending.as_ref().is_some_and(|batch| !batch.received()) {
                *pending = None;
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = pending;
        }
    }
    pub fn bytes(&self) -> &[u8] {
        self.batch.bytes()
    }
    pub fn count(&self) -> u32 {
        self.batch.count()
    }
    pub fn expired(&self) -> bool {
        self.batch.expired()
    }
    pub fn trace(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.trace
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.batch.signal() == Signal::Traces
        }
    }
    pub fn attempts(&self) -> u32 {
        #[cfg(not(target_arch = "wasm32"))]
        {
            0
        }
        #[cfg(target_arch = "wasm32")]
        {
            u32::from(self.batch.attempts())
        }
    }
    pub fn received(&self) -> bool {
        self.accepted.is_some()
    }
    pub fn receive(&mut self, receipt: &crate::observability_wire::IngressReceipt) -> bool {
        if self.received() {
            return false;
        }
        self.accepted = super::receipt::accepted_count(self.trace(), self.count(), receipt);
        self.received()
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn full_receipt(&self) -> bool {
        self.accepted == Some(i64::from(self.count()))
    }
    pub async fn acknowledge(&mut self, source: &Source) -> Result<(), ()> {
        let accepted = self.accepted.ok_or(())?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = source;
            self.batch.acknowledge_count(accepted).map_err(|_| ())
        }
        #[cfg(target_arch = "wasm32")]
        {
            source.remember(
                self.sender.acknowledge_count(&self.batch, accepted).await,
                false,
            )
        }
    }
    pub async fn failed(&self, source: &Source) -> Result<(), ()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = source;
            self.batch.failed();
            Ok(())
        }
        #[cfg(target_arch = "wasm32")]
        {
            source.remember(self.sender.failed(&self.batch).await, false)
        }
    }
    pub async fn discard(self, source: &Source) -> Result<(), ()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = source;
            drop(self);
            Ok(())
        }
        #[cfg(target_arch = "wasm32")]
        {
            source.remember(self.sender.discard(&self.batch).await, false)
        }
    }
}
