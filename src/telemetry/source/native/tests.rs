use super::*;
use crate::telemetry::native_queue::tests::config;
use nddev_device_sync_telemetry::{ExportFeed, subscriber};
use opentelemetry::trace::TracerProvider;
use std::sync::Mutex;

fn empty_feed() -> ExportFeed {
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::default();
    let (_, control) = subscriber(
        config(),
        std::io::sink(),
        provider.tracer("spool-readiness"),
    )
    .unwrap();
    control.subscribe().unwrap()
}
fn source() -> Source {
    Source {
        events: Arc::new(empty_feed()),
        traces: Arc::new(empty_feed()),
        scope: "a".repeat(64),
        native: Mutex::default(),
    }
}
fn ready(source: &Source) -> Option<bool> {
    let mut view = DeliveryView::default();
    source.snapshot(&mut view);
    view.local_persistence_ready
}
#[test]
fn an_old_write_or_new_metadata_read_cannot_claim_recovery_after_failure() {
    let source = source();
    source
        .remember_native(
            Ok(disk::Health {
                revision: 1,
                ..Default::default()
            }),
            Some(0),
        )
        .unwrap();
    assert_eq!(ready(&source), Some(true));
    assert!(source.remember_native(Err(()), None).is_err());
    assert_eq!(ready(&source), Some(false));
    source
        .remember_native(
            Ok(disk::Health {
                revision: 2,
                ..Default::default()
            }),
            Some(0),
        )
        .unwrap();
    assert_eq!(ready(&source), Some(false));
    source
        .remember_native(
            Ok(disk::Health {
                revision: 3,
                ..Default::default()
            }),
            None,
        )
        .unwrap();
    assert_eq!(ready(&source), Some(false));
    source
        .remember_native(
            Ok(disk::Health {
                revision: 4,
                ..Default::default()
            }),
            Some(1),
        )
        .unwrap();
    assert_eq!(ready(&source), Some(true));
}
#[derive(Clone)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn loss_classes_are_schema_valid_aggregated_and_do_not_feed_the_exporter() {
    let source = source();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::default();
    let (subscriber, control) = subscriber(
        config(),
        Output(bytes.clone()),
        provider.tracer("spool-loss"),
    )
    .unwrap();
    let feed = control.subscribe().unwrap();
    tracing::subscriber::with_default(subscriber, || {
        source
            .remember_native(
                Ok(disk::Health {
                    revision: 1,
                    ..Default::default()
                }),
                None,
            )
            .unwrap();
        source
            .remember_native(
                Ok(disk::Health {
                    revision: 2,
                    losses: [2, 0, 0, 0, 0, 0],
                    ..Default::default()
                }),
                None,
            )
            .unwrap();
        source
            .remember_native(
                Ok(disk::Health {
                    revision: 3,
                    losses: [3, 0, 0, 0, 0, 0],
                    ..Default::default()
                }),
                None,
            )
            .unwrap();
        source.native.lock().unwrap().loss_reported_at =
            Some(std::time::Instant::now() - Duration::from_secs(31));
        source
            .remember_native(
                Ok(disk::Health {
                    revision: 4,
                    losses: [5, 0, 0, 0, 0, 0],
                    ..Default::default()
                }),
                None,
            )
            .unwrap();
    });
    let records: Vec<serde_json::Value> = bytes
        .lock()
        .unwrap()
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    for record in &records {
        nddev_device_sync_telemetry::decode_event(record.clone()).unwrap();
        assert_eq!(record["event.name"], "telemetry.spool.expired");
    }
    assert_eq!(
        records
            .iter()
            .map(|r| r["dropped_count"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(feed.health().pending, 0);
}
