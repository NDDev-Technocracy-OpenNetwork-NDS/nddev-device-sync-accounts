//! Admission unit tests use owned memory work, never a credential provider or
//! authentication fixture. Real native-store acceptance is a separate gate.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn read_diagnostics_do_not_hide_failures_or_mutation_audit() {
    use nddev_device_sync_telemetry::{Config, DebugWindow};
    use opentelemetry::trace::TracerProvider;
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut output = self.0.lock().unwrap();
            assert!(output.len() + bytes.len() <= 65_536);
            output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let (subscriber, control) = nddev_device_sync_telemetry::subscriber(
        Config {
            service: "nds-store-policy-acceptance".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-accounts".into(),
            commit: "unknown".into(),
            channel: "alpha".into(),
            standards: "unreleased".into(),
            environment: "test".into(),
            target_prefixes: vec!["nds_accounts".into()],
            default_module: "accounts".into(),
            debug: None,
        },
        Capture(output.clone()),
        provider.tracer("store-policy-acceptance"),
    )
    .unwrap();
    tracing::subscriber::with_default(subscriber, || {
        nddev_device_sync_telemetry::operation_span("accounts", "io")
            .unwrap()
            .in_scope(|| {
                for _ in 0..100 {
                    report_io("identity.credential.read", &Ok(()), 1);
                    report_io("identity.offline.fence.read", &Ok(()), 1);
                }
                report_io("identity.credential.write", &Ok(()), 1);
                report_io("identity.credential.delete", &Ok(()), 1);
                report_io("identity.offline.fence", &Ok(()), 1);
                report_io(
                    "identity.credential.read",
                    &Err::<(), _>(ClientError::CredentialStore),
                    1,
                );
                report_io(
                    "identity.offline.fence.read",
                    &Err::<(), _>(ClientError::Busy),
                    1,
                );
                control
                    .set_debug(Some(DebugWindow {
                        scope: "io".into(),
                        duration: Duration::from_secs(30),
                        events: 2,
                    }))
                    .unwrap();
                report_io("identity.credential.read", &Ok(()), 1);
                report_io("identity.offline.fence.read", &Ok(()), 1);
                report_io("identity.credential.read", &Ok(()), 1);
                report_io(
                    "identity.credential.read",
                    &Err::<(), _>(ClientError::Timeout),
                    1,
                );
            });
    });
    assert!(!control.debug_active());
    assert_eq!(control.rejected_fields_or_events(), 0);
    let events: Vec<serde_json::Value> = output
        .lock()
        .unwrap()
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|line| {
            let event: serde_json::Value = serde_json::from_slice(line).unwrap();
            nddev_device_sync_telemetry::decode_event(event.clone()).unwrap();
            event
        })
        .collect();
    let identities: Vec<_> = events
        .iter()
        .filter(|e| e["event.name"].as_str().unwrap().starts_with("identity."))
        .collect();
    assert_eq!(identities.len(), 8);
    for (event, severity) in identities.iter().zip([
        "info", "info", "info", "warn", "warn", "debug", "debug", "warn",
    ]) {
        assert_eq!(event["severity"], severity);
        assert_eq!(event["module"], "accounts");
        assert_eq!(event["scope"], "io");
        assert!(event["trace_id"].as_str().is_some_and(|id| id.len() == 32));
    }
    assert!(
        events
            .iter()
            .any(|event| event["event.name"] == "logging.debug.disabled")
    );
}

#[tokio::test]
async fn cancelled_caller_keeps_running_work_owned_and_waiters_can_cancel() {
    let store =
        SessionStore::for_endpoint(&format!("https://nds-io-{}.invalid/", uuid::Uuid::new_v4()))
            .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let running = {
        let store = store.clone();
        let calls = calls.clone();
        tokio::spawn(async move {
            store
                .run_io("identity.credential.read", move |_, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let _ = started.send(());
                    wait.recv_timeout(Duration::from_secs(5))
                        .map_err(|_| ClientError::Timeout)?;
                    Ok(())
                })
                .await
        })
    };
    ready.await.unwrap();
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());

    // A foreground identity mutation can wait behind background I/O. Its
    // process lease is not created before dispatch, and cancellation releases
    // local mutation admission without releasing the still-running worker.
    let local = store.operation().unwrap();
    let mut identity = Box::pin(store.activate_operation(local));
    assert!(futures::poll!(identity.as_mut()).is_pending());
    assert!(matches!(store.operation(), Err(ClientError::Busy)));
    drop(identity);
    drop(store.operation().unwrap());

    let queued_calls = calls.clone();
    let mut queued = Box::pin(store.run_io("identity.credential.read", move |_, _| {
        queued_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }));
    assert!(futures::poll!(queued.as_mut()).is_pending());
    drop(queued);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let next_calls = calls.clone();
    let mut next = Box::pin(store.run_io("identity.credential.read", move |_, _| {
        Ok(next_calls.fetch_add(1, Ordering::SeqCst) + 1)
    }));
    assert!(futures::poll!(next.as_mut()).is_pending());
    release.send(()).unwrap();
    assert_eq!(next.await.unwrap(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn io_waiting_budget_is_bounded_and_cancelled_requests_release_capacity() {
    let store = SessionStore::for_endpoint(&format!(
        "https://nds-io-budget-{}.invalid/",
        uuid::Uuid::new_v4()
    ))
    .unwrap();
    let span = tracing::Span::none();
    let active = store.admit_io(&span).await.unwrap();
    let mut waiting = Vec::new();
    for _ in 1..MAX_IO_REQUESTS {
        let mut next = Box::pin(store.admit_io(&span));
        assert!(futures::poll!(next.as_mut()).is_pending());
        waiting.push(next);
    }
    assert!(matches!(
        store.admit_io(&span).await,
        Err(ClientError::Busy)
    ));
    waiting.pop();
    let mut replacement = Box::pin(store.admit_io(&span));
    assert!(futures::poll!(replacement.as_mut()).is_pending());
    drop(waiting);
    drop(active);
    let (permit, remaining) = replacement.await.unwrap();
    assert!(!remaining.is_zero() && remaining <= IO_TIMEOUT);
    drop(permit);
    drop(store.admit_io(&span).await.unwrap());
}
