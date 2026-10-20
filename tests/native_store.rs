use nddev_device_sync_accounts::SessionStore;
use nddev_device_sync_telemetry::{Config, DebugWindow};
use opentelemetry::trace::TracerProvider;
use tracing::instrument::WithSubscriber;

struct OwnedLog(std::path::PathBuf);
impl Drop for OwnedLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
#[ignore = "requires the user's actual unlocked native credential service"]
async fn owned_ephemeral_entry_round_trips_and_is_deleted() {
    for debug in [false, true] {
        let log =
            OwnedLog(std::env::temp_dir().join(format!("nds-store-{}.log", uuid::Uuid::new_v4())));
        let output = std::fs::File::create_new(&log.0).unwrap();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let (subscriber, control) = nddev_device_sync_telemetry::subscriber(
            Config {
                service: "nds-native-store-acceptance".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-accounts".into(),
                commit: "unknown".into(),
                channel: "alpha".into(),
                standards: "unreleased".into(),
                environment: "test".into(),
                target_prefixes: vec!["nds_accounts".into()],
                default_module: "accounts".into(),
                debug: debug.then(|| DebugWindow {
                    scope: "io".into(),
                    duration: std::time::Duration::from_secs(30),
                    events: 32,
                }),
            },
            output,
            provider.tracer("native-store-acceptance"),
        )
        .unwrap();
        let scope = format!("https://nds-test-{}.invalid/", uuid::Uuid::new_v4());
        let value = uuid::Uuid::new_v4().to_string();
        async {
            let store = SessionStore::for_endpoint(&scope).unwrap();
            assert!(store.read().await.unwrap().is_none());
            store.write(value.as_bytes()).await.unwrap();
            let restored = SessionStore::for_endpoint(&scope).unwrap();
            let read = restored.read().await;
            let deleted = restored.delete().await;
            deleted.unwrap();
            assert_eq!(read.unwrap().unwrap().as_slice(), value.as_bytes());
            assert!(store.read().await.unwrap().is_none());
        }
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;
        assert_eq!(control.rejected_fields_or_events(), 0);
        drop(control);
        let bytes = std::fs::read_to_string(&log.0).unwrap();
        assert!(!bytes.contains(&scope) && !bytes.contains(&value));
        let events: Vec<_> = bytes
            .lines()
            .map(|line| {
                nddev_device_sync_telemetry::decode_event(serde_json::from_str(line).unwrap())
                    .unwrap()
            })
            .collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_name.starts_with("identity."))
                .filter(|event| matches!(
                    event.outcome,
                    Some(nddev_device_sync_telemetry::event::Outcome::OutcomeOk)
                ))
                .map(|event| event.event_name.as_str())
                .collect::<Vec<_>>(),
            if debug {
                vec![
                    "identity.credential.read",
                    "identity.credential.write",
                    "identity.credential.read",
                    "identity.credential.delete",
                    "identity.credential.read",
                ]
            } else {
                vec!["identity.credential.write", "identity.credential.delete"]
            }
        );
        for event in events
            .into_iter()
            .filter(|event| event.event_name.starts_with("identity."))
        {
            assert_eq!(event.module, "accounts");
            assert_eq!(event.trace_id.as_ref().unwrap().len(), 32);
            assert_eq!(event.span_id.as_ref().unwrap().len(), 16);
        }
    }
}
