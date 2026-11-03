//! Admission unit tests use owned memory work, never a credential provider or
//! authentication fixture. Real native-store acceptance is a separate gate.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn read_diagnostics_do_not_hide_failures_or_mutation_audit() {
    use nddev_device_sync_telemetry::client_traces::ClientTraces;
    use nddev_device_sync_telemetry::{Config, DebugWindow};
    use opentelemetry::trace::TraceContextExt;
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
    let config = Config {
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
    };
    let traces = ClientTraces::new(&config).unwrap();
    let feed = traces.subscribe().unwrap();
    let (subscriber, control) =
        nddev_device_sync_telemetry::subscriber(config, Capture(output.clone()), traces.tracer())
            .unwrap();
    tracing::subscriber::with_default(subscriber, || {
        let complete = |event, result: Result<(), ClientError>| {
            io_span(event)
                .unwrap()
                .in_scope(|| report_io(event, &result, 1));
        };
        nddev_device_sync_telemetry::operation_span("vault", "process")
            .unwrap()
            .in_scope(|| {
                for _ in 0..100 {
                    complete("identity.credential.read", Ok(()));
                    complete("identity.offline.fence.read", Ok(()));
                    complete("identity.operation.admitted", Ok(()));
                }
                complete("identity.credential.write", Ok(()));
                complete("identity.credential.delete", Ok(()));
                complete("identity.offline.fence", Ok(()));
                complete(
                    "identity.credential.read",
                    Err(ClientError::CredentialStore),
                );
                complete("identity.offline.fence.read", Err(ClientError::Busy));
                control
                    .set_debug(Some(DebugWindow {
                        scope: "io".into(),
                        duration: Duration::from_secs(30),
                        events: 2,
                    }))
                    .unwrap();
                complete("identity.credential.read", Ok(()));
                complete("identity.offline.fence.read", Ok(()));
                complete("identity.credential.read", Ok(()));
                complete("identity.credential.read", Err(ClientError::Timeout));
            });
        for _ in 0..100 {
            for event in [
                "identity.credential.read",
                "identity.offline.fence.read",
                "identity.operation.admitted",
            ] {
                let standalone = io_span(event).unwrap();
                assert!(
                    !nddev_device_sync_telemetry::trace_context(&standalone)
                        .span()
                        .span_context()
                        .is_valid()
                );
                standalone.in_scope(|| report_io(event, &Ok::<(), ClientError>(()), 1));
            }
        }
    });
    // Only the actual parent and three mutations retain real spans. Repeated
    // nested or standalone maintenance cannot fill the 128-span feed.
    assert_eq!(feed.health().pending, 4);
    assert_eq!(feed.health().dropped, 0);
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
async fn signed_requests_wait_fairly_and_cancelled_waiters_release_capacity() {
    let store = SessionStore::for_endpoint(&format!(
        "https://nds-signed-{}.invalid/",
        uuid::Uuid::new_v4()
    ))
    .unwrap();
    let active = store.operation().unwrap();
    let mut waiting = Vec::new();
    for _ in 0..MAX_SIGNED_WAITERS {
        let mut future = Box::pin(store.signed_operation());
        assert!(futures::poll!(future.as_mut()).is_pending());
        waiting.push(future);
    }
    assert!(matches!(
        store.signed_operation().await,
        Err(ClientError::Busy)
    ));
    waiting.pop();
    let mut replacement = Box::pin(store.signed_operation());
    assert!(futures::poll!(replacement.as_mut()).is_pending());
    drop(active);
    let first = waiting.remove(0).await.unwrap();
    assert!(futures::poll!(replacement.as_mut()).is_pending());
    assert!(matches!(store.operation(), Err(ClientError::Busy)));
    drop(first);
    for future in waiting {
        drop(future.await.unwrap());
    }
    drop(replacement.await.unwrap());
    drop(store.operation().unwrap());
}

#[tokio::test]
async fn queued_signed_request_cannot_retarget_after_client_cancellation() {
    let client = crate::IdentityClient::new(&format!(
        "https://nds-queued-{}.invalid/",
        uuid::Uuid::new_v4()
    ))
    .unwrap();
    let active = client.store.operation().unwrap();
    let mut request = Box::pin(client.sync_request(crate::SyncRequest::TelemetryPolicy));
    assert!(futures::poll!(request.as_mut()).is_pending());
    client.cancel();
    drop(active);
    assert!(matches!(
        request.await,
        Err(ClientError::RevalidationRequired)
    ));
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

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn delivery_admission_io_remains_outside_the_trace_export_feed() {
    use nddev_device_sync_telemetry::{Config, client_traces::ClientTraces};
    use tracing::Instrument;
    use tracing::instrument::WithSubscriber;
    let config = Config {
        service: "nds-delivery-io-regression".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-accounts".into(),
        commit: "unknown".into(),
        channel: "alpha".into(),
        standards: "unreleased".into(),
        environment: "test".into(),
        target_prefixes: vec!["nds_accounts".into()],
        default_module: "process".into(),
        debug: None,
    };
    let traces = ClientTraces::new(&config).unwrap();
    let feed = traces.subscribe().unwrap();
    let (subscriber, control) =
        nddev_device_sync_telemetry::subscriber(config, std::io::sink(), traces.tracer()).unwrap();
    async {
        let store = SessionStore::for_endpoint(&format!(
            "https://nds-delivery-{}.invalid",
            uuid::Uuid::new_v4()
        ))
        .unwrap();
        for _ in 0..10 {
            let span = nddev_device_sync_telemetry::delivery_span();
            store
                .run_io("identity.operation.admitted", |_, _| Ok(()))
                .instrument(span)
                .await
                .unwrap();
        }
        assert_eq!(
            feed.health().pending,
            0,
            "delivery credential admission created recursive spans"
        );
        assert_eq!(control.rejected_fields_or_events(), 0);
    }
    .with_subscriber(subscriber)
    .await;
}

/// Exercise native dispatch and cross-process ownership without accessing a
/// credential provider. A fresh bounded child isolates unrelated test FDs.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn completed_native_dispatch_and_leases_keep_file_descriptors_bounded() {
    use std::os::unix::fs::DirBuilderExt;
    const CHILD: &str = "NDS_NATIVE_DISPATCH_FD_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let directory =
            std::env::temp_dir().join(format!("nds-native-fd-unit-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "completed_native_dispatch_and_leases_keep_file_descriptors_bounded",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env("XDG_STATE_HOME", &directory)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                std::fs::remove_dir_all(&directory).unwrap();
                assert!(status.success(), "Native dispatch FD child failed");
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                std::fs::remove_dir_all(&directory).unwrap();
                panic!("Native dispatch FD child exceeded its deadline");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    // SAFETY: only this fresh test child lowers its own soft limit; the parent,
    // other tests and inherited hard limit remain unchanged.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = limit.rlim_cur.min(256);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
    let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let store = SessionStore::for_endpoint(&format!(
        "https://nds-native-fd-{}.invalid/",
        uuid::Uuid::new_v4()
    ))
    .unwrap();
    for _ in 0..32 {
        let permit = store
            .activate_operation(store.operation().unwrap())
            .await
            .unwrap();
        store
            .run_io("identity.credential.read", |_, _| Ok(()))
            .await
            .unwrap();
        drop(permit);
    }
    let before = count();
    for _ in 0..2048 {
        let permit = store
            .activate_operation(store.operation().unwrap())
            .await
            .unwrap();
        store
            .run_io("identity.credential.read", |_, _| Ok(()))
            .await
            .unwrap();
        drop(permit);
    }
    let after = count();
    eprintln!("Native dispatch/lease FDs before={before}, after={after}");
    assert!(
        after <= before + 4,
        "Completed native I/O retained file descriptors"
    );
}
