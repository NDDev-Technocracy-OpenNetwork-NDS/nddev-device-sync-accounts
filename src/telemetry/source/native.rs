//! Native staging shares the sender's original authenticated scope. Blocking
//! commits retain their queue lease and batch even if an async waiter disappears.
use super::{Batch, Source, add};
use crate::{runtime, telemetry::native_queue as disk, view::DeliveryView};
use nddev_device_sync_telemetry::{ExportBatch, ExportFeed};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub(super) struct State {
    queue: Option<Arc<disk::Queue>>,
    health: Option<disk::Health>,
    initialised: bool,
    staging: bool,
    writing: bool,
    ready: bool,
    observed: bool,
    io_failures: u64,
    fallback: VecDeque<(ExportBatch, bool)>,
}
pub(super) enum Payload {
    Memory(ExportBatch, bool),
    Stored(disk::Batch, Arc<disk::Queue>),
}
impl Payload {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Memory(b, _) => b.bytes(),
            Self::Stored(b, _) => &b.bytes,
        }
    }
    pub fn count(&self) -> u32 {
        match self {
            Self::Memory(b, _) => b.count(),
            Self::Stored(b, _) => b.count,
        }
    }
    pub fn expired(&self) -> bool {
        match self {
            Self::Memory(b, _) => b.expired(),
            Self::Stored(b, q) => q.expired(b),
        }
    }
    pub fn trace(&self) -> bool {
        match self {
            Self::Memory(_, trace) => *trace,
            Self::Stored(b, _) => b.trace,
        }
    }
    pub fn attempts(&self) -> u32 {
        match self {
            Self::Memory(..) => 0,
            Self::Stored(b, _) => b.attempts,
        }
    }
    pub async fn acknowledge(&mut self, source: &Source, accepted: i64) -> Result<(), ()> {
        match self {
            Self::Memory(b, _) => b.acknowledge_count(accepted).map_err(|_| ()),
            Self::Stored(b, q) => source.remember_native(q.finish(b, Some(accepted)).await, false),
        }
    }
    pub async fn failed(&self, source: &Source) -> Result<(), ()> {
        match self {
            Self::Memory(b, _) => {
                b.failed();
                Ok(())
            }
            Self::Stored(b, q) => source.remember_native(q.failed(b).await, false),
        }
    }
    pub async fn discard(self, source: &Source) -> Result<(), ()> {
        match self {
            Self::Memory(..) => Ok(()),
            Self::Stored(b, q) => source.remember_native(q.finish(&b, None).await, false),
        }
    }
}
impl Source {
    pub(in crate::telemetry) fn native_busy(&self) -> bool {
        let state = self.native.lock().unwrap_or_else(|e| e.into_inner());
        !state.initialised || state.writing
    }
    pub(super) fn snapshot_native(&self, view: &mut DeliveryView) {
        let state = self.native.lock().unwrap_or_else(|e| e.into_inner());
        view.local_persistence_ready = state.observed.then_some(state.ready);
        view.failures = add(view.failures, state.io_failures);
        if let Some(h) = &state.health {
            view.pending += h.events.pending;
            view.spans_pending += h.traces.pending;
            view.delivered = add(view.delivered, h.events.delivered);
            view.spans_delivered = add(view.spans_delivered, h.traces.delivered);
            view.dropped = add(view.dropped, h.events.dropped);
            view.spans_dropped = add(view.spans_dropped, h.traces.dropped);
            view.failures = add(view.failures, h.events.failures);
            view.spans_failures = add(view.spans_failures, h.traces.failures);
            view.last_success_at = view.last_success_at.max(h.last_success_at);
        }
    }
    fn native_queue(&self) -> Option<Arc<disk::Queue>> {
        self.native
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue
            .clone()
    }
    fn remember_native(&self, result: Result<disk::Health, ()>, write: bool) -> Result<(), ()> {
        let mut state = self.native.lock().unwrap_or_else(|e| e.into_inner());
        let mut transition = None;
        let result = match result {
            Ok(health) => {
                if state
                    .health
                    .as_ref()
                    .is_none_or(|old| old.revision <= health.revision)
                {
                    state.health = Some(health);
                }
                if write {
                    if !state.observed || !state.ready {
                        transition = Some(true);
                    }
                    state.ready = true;
                    state.observed = true;
                    state.staging = true;
                }
                Ok(())
            }
            Err(()) => {
                if !state.observed || state.ready {
                    transition = Some(false);
                }
                state.observed = true;
                state.ready = false;
                state.staging = false;
                state.io_failures = add(state.io_failures, 1);
                Err(())
            }
        };
        drop(state);
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
    pub(super) async fn maintain_native(&self) {
        if let Some(q) = self.native_queue() {
            let _ = self.remember_native(q.health().await, false);
        }
    }
    pub(super) async fn enabled_native(&self, enabled: bool) -> Result<(), ()> {
        if let Some(q) = self.native_queue() {
            self.remember_native(q.enabled(enabled).await, false)?;
        }
        Ok(())
    }
    pub(super) async fn next_native(&self, prefer_trace: bool) -> Result<Option<Batch>, ()> {
        let (q, initialised) = {
            let state = self.native.lock().unwrap_or_else(|e| e.into_inner());
            (state.queue.clone(), state.initialised)
        };
        if !initialised {
            return Ok(None);
        }
        if let Some(q) = q {
            match q.next().await {
                Ok(Some(batch)) => {
                    return Ok(Some(Batch {
                        batch: Payload::Stored(batch, q),
                        accepted: None,
                    }));
                }
                Ok(None) => {}
                Err(()) => {
                    let _ = self.remember_native(Err(()), false);
                }
            }
        }
        let fallback = {
            self.native
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .fallback
                .pop_front()
        };
        if let Some((batch, trace)) = fallback {
            return Ok(Some(Batch {
                batch: Payload::Memory(batch, trace),
                accepted: None,
            }));
        }
        if self
            .native
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .staging
        {
            return Ok(None);
        }
        let take = |feed: &ExportFeed, trace| feed.take_batch().map(|b| (b, trace));
        let selected = if prefer_trace {
            take(&self.traces, true).or_else(|| take(&self.events, false))
        } else {
            take(&self.events, false).or_else(|| take(&self.traces, true))
        };
        Ok(selected.map(|(batch, trace)| Batch {
            batch: Payload::Memory(batch, trace),
            accepted: None,
        }))
    }
    pub(super) fn start_native_staging(self: &Arc<Self>, cancel: CancellationToken) {
        let source = self.clone();
        runtime::spawn(async move {
            let scope = source.scope.clone();
            let opened = tokio::task::spawn_blocking(move || {
                let root = crate::private_data_directory().map_err(|_| ())?;
                if std::fs::symlink_metadata(&root).is_ok_and(|m| !m.file_type().is_dir()) {
                    return Err(());
                }
                disk::Queue::open(root.join("telemetry"), scope)
            })
            .await
            .map_err(|_| ())
            .and_then(|r| r);
            let q = match opened {
                Ok(q) => {
                    let mut state = source.native.lock().unwrap_or_else(|e| e.into_inner());
                    state.queue = Some(q.clone());
                    state.initialised = true;
                    state.staging = true;
                    q
                }
                Err(()) => {
                    source
                        .native
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .initialised = true;
                    let _ = source.remember_native(Err(()), false);
                    return;
                }
            };
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                let mut work = false;
                let mut failed = false;
                for (feed, trace) in [(&source.events, false), (&source.traces, true)] {
                    if cancel.is_cancelled() {
                        break;
                    }
                    if let Some(batch) = feed.take_batch() {
                        work = true;
                        source
                            .native
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .writing = true;
                        match q.persist(trace, batch).await {
                            Ok((h, written)) => {
                                let _ = source.remember_native(Ok(h), written);
                            }
                            Err(batch) => {
                                let _ = source.remember_native(Err(()), false);
                                if let Some(batch) = batch {
                                    source
                                        .native
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .fallback
                                        .push_back((batch, trace));
                                }
                                failed = true;
                            }
                        }
                        source
                            .native
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .writing = false;
                    }
                }
                if failed {
                    tokio::select! {_=cancel.cancelled()=>break,_=runtime::sleep(Duration::from_secs(5))=>{}}
                } else if !work {
                    tokio::select! {_=cancel.cancelled()=>break,_=source.events.ready()=>{},_=source.traces.ready()=>{},_=runtime::sleep(Duration::from_millis(200))=>{}}
                }
            }
        });
    }
}
