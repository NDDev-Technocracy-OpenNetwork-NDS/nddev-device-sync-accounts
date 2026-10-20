use super::*;
use nddev_device_sync_telemetry::{
    Config,
    client_traces::ClientTraces,
    view::{ClientLifecycle, FailureKind},
};
use opentelemetry::trace::TraceContextExt;
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "requires owned PostgreSQL/Mailpit/Vector/OpenObserve fixtures and unlocked native credential store"]
async fn actual_signed_client_delivery_and_incidents() {
    let receipt = std::path::PathBuf::from(std::env::var("NDS_FIXTURE_RECEIPT").unwrap());
    let fixture: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    let endpoint = fixture["base_url"].as_str().unwrap();
    let mailbox = fixture["mailpit_url"].as_str().unwrap();
    assert!(endpoint.starts_with("http://127.0.0.1:") && mailbox.starts_with("http://127.0.0.1:"));
    assert_eq!(fixture["status"], "running");
    let config = Config {
        service: "nddev-device-sync-client".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-desktop".into(),
        commit: "unknown".into(),
        channel: "alpha".into(),
        standards: "unreleased".into(),
        environment: "test".into(),
        target_prefixes: vec!["nds_accounts".into()],
        default_module: "accounts".into(),
        debug: None,
    };
    let traces = ClientTraces::new(&config).unwrap();
    let mut logger = nddev_device_sync_telemetry::install_client_with_tracer_to(
        config,
        traces.tracer(),
        nddev_device_sync_telemetry::LocalOutput::Stdout,
    )
    .unwrap();
    std::panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            eprintln!("Native acceptance assertion at line {}", location.line());
        }
    }));
    let identity = Arc::new(IdentityClient::new(endpoint).unwrap());
    let previous = identity.refresh().await.unwrap();
    if previous.authenticated {
        // This explicitly owned loopback fixture may be retried after a failed
        // assertion. Remove only its own native entries, never a live keychain.
        identity.logout().await.unwrap();
        identity
            .store
            .device_store(&previous.tenant_id, &previous.user_id)
            .delete()
            .await
            .unwrap();
    }
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let previous_messages: Value = http
        .get(format!("{mailbox}/api/v1/messages"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let previous_ids: Vec<String> = previous_messages["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|message| message["ID"].as_str().map(str::to_owned))
        .collect();
    identity
        .request_email(fixture["owner_email"].as_str().unwrap().into(), "en")
        .await
        .unwrap();
    let code = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let messages: Value = http
                .get(format!("{mailbox}/api/v1/messages"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if let Some(id) = messages["messages"]
                .as_array()
                .and_then(|items| items.first())
                .and_then(|message| message["ID"].as_str())
                .filter(|id| !previous_ids.iter().any(|previous| previous == id))
            {
                let message: Value = http
                    .get(format!("{mailbox}/api/v1/message/{id}"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if let Some((_, code)) = message["Text"].as_str().unwrap().split_once("code: ") {
                    let code = code.chars().take(8).collect::<String>();
                    if code.len() == 8 && code.bytes().all(|b| b.is_ascii_digit()) {
                        break code;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    identity.verify_email(code).await.unwrap();
    let view = identity
        .prepare_device("Native delivery acceptance".into())
        .await
        .unwrap();
    let baseline: wire::IncidentPage = serde_json::from_slice(
        &identity
            .sync_request(SyncRequest::Incidents {
                after: String::new(),
            })
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    let previous_incidents: Vec<String> = baseline
        .incidents
        .into_iter()
        .map(|incident| incident.incident_id)
        .collect();
    let events = logger.control.subscribe().unwrap();
    let native = traces.subscribe().unwrap();
    let delivery = Delivery::start(identity.clone(), events, native, true);
    let span = nddev_device_sync_telemetry::operation_span("accounts", "process").unwrap();
    let trace_id = nddev_device_sync_telemetry::trace_context(&span)
        .span()
        .span_context()
        .trace_id()
        .to_string();
    span.in_scope(|| logger.control.report_failure(FailureKind::FlutterFramework));
    drop(span);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let health = delivery.snapshot();
            if health.delivered >= 1
                && health.spans_delivered >= 1
                && health.pending + health.spans_pending == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("actual signed native feeds were not acknowledged");
    let before = delivery.snapshot();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        delivery.snapshot().delivered,
        before.delivered,
        "delivery generated its own event feedback"
    );
    assert_eq!(
        delivery.snapshot().spans_delivered,
        before.spans_delivered,
        "delivery generated its own span feedback"
    );
    let page: wire::IncidentPage = serde_json::from_slice(
        &identity
            .sync_request(SyncRequest::Incidents {
                after: String::new(),
            })
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    let incident = page
        .incidents
        .into_iter()
        .find(|incident| {
            incident
                .service_name
                .starts_with("nddev-device-sync-client.")
                && !previous_incidents.contains(&incident.incident_id)
                && matches!(incident.state, wire::IncidentState::Open)
        })
        .expect("actual client failure did not open an incident");
    let body = serde_json::to_vec(&wire::IncidentAction {
        operation_id: uuid::Uuid::now_v7().to_string(),
        expected_revision: incident.revision,
    })
    .unwrap();
    let action = || SyncRequest::IncidentAction {
        id: incident.incident_id.clone(),
        silence: false,
        body: body.clone(),
    };
    let first = identity.sync_request(action()).await.unwrap();
    let replay = identity.sync_request(action()).await.unwrap();
    assert_eq!(first.body, replay.body);
    let ack: wire::Incident = serde_json::from_slice(&first.body).unwrap();
    assert!(matches!(ack.state, wire::IncidentState::Acknowledged));
    delivery.foreground(false);
    logger
        .control
        .report_client_lifecycle(ClientLifecycle::Ready);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(delivery.snapshot().paused && delivery.snapshot().pending > 0);
    assert_eq!(delivery.snapshot().delivered, before.delivered);
    fixture_mode(&receipt, &fixture, "offline").await;
    delivery.foreground(true);
    tokio::time::timeout(Duration::from_secs(12), async {
        while delivery.snapshot().failures == before.failures {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("a real server disconnect did not degrade delivery");
    assert!(delivery.snapshot().pending > 0);
    assert_eq!(delivery.snapshot().delivered, before.delivered);
    fixture_mode(&receipt, &fixture, "online").await;
    // A transport failure revokes online authority. The application owns its
    // existing authorization reconciliation; the exporter must not bypass it
    // or become a second identity owner just to retry telemetry.
    assert!(!identity.authority_online());
    tokio::time::timeout(Duration::from_secs(15), async {
        while !identity.authority_online() {
            identity.maintain_authorization().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("ordinary signed authority reconciliation did not recover");
    assert_eq!(identity.view().current_device_id, view.current_device_id);
    tokio::time::timeout(Duration::from_secs(20), async {
        while delivery.snapshot().pending + delivery.snapshot().spans_pending > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("retained telemetry did not drain after the real server restarted");
    let after = delivery.flush().await;
    assert_eq!(after.pending + after.spans_pending, 0);
    assert_eq!(after.dropped + after.spans_dropped, 0);
    drop(delivery);
    // Released subscription ownership must permit an immediate same-process
    // reconnect even while the cancelled task is still being dropped.
    let replacement = logger.control.subscribe().unwrap();
    drop(replacement);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let page: wire::IncidentPage = serde_json::from_slice(
        &identity
            .sync_request(SyncRequest::Incidents {
                after: String::new(),
            })
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(
        page.incidents
            .iter()
            .any(|item| item.incident_id == incident.incident_id
                && matches!(item.state, wire::IncidentState::Resolved))
    );
    // Independently query the actual indexing backend, not only gateway ACKs.
    let obs: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("NDS_OBSERVABILITY_FIXTURE_RECEIPT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(obs["status"], "running");
    let query: Value =
        serde_json::from_slice(&std::fs::read(obs["query_config"].as_str().unwrap()).unwrap())
            .unwrap();
    let origin = query["origin"].as_str().unwrap();
    assert!(origin.starts_with("http://127.0.0.1:"));
    let user = query["user"].as_str().unwrap();
    let password = query["password"].as_str().unwrap();
    let searchable_logs = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
            let body = json!({"query":{"sql":format!("SELECT * FROM nds WHERE trace_id='{trace_id}' AND event_name='client.failure'"),"start_time":now-3_600_000_000u64,"end_time":now+2_000_000,"from":0,"size":20}});
            let result: Value = http.post(format!("{origin}/api/default/_search?type=logs")).basic_auth(user, Some(password)).json(&body).send().await.unwrap().json().await.unwrap();
            if let Some(hits) = result["hits"].as_array().filter(|hits| !hits.is_empty()) {
                assert_eq!(hits.len(), 1, "the actual event was indexed more than once");
                let event = &hits[0];
                assert_eq!(event["device_id"], view.current_device_id);
                assert_eq!(event["user_id"], view.user_id);
                assert_eq!(event["tenant_id"], view.tenant_id);
                assert_eq!(event["error_type"], "flutter_framework_error");
                break hits.len();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("gateway ACK did not become a searchable, authenticated log");
    let streams: Value = http
        .get(format!("{origin}/api/default/streams?type=traces"))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let native_count = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let mut count = 0;
            for stream in streams["list"].as_array().unwrap() {
                let table = stream["name"].as_str().unwrap();
                assert!(table.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
                let body = json!({"query":{"sql":format!("SELECT * FROM \"{table}\" WHERE trace_id='{trace_id}'"),"start_time":now-3_600_000_000u64,"end_time":now+2_000_000,"from":0,"size":20}});
                let result: Value = http.post(format!("{origin}/api/default/_search?type=traces")).basic_auth(user, Some(password)).json(&body).send().await.unwrap().json().await.unwrap();
                if let Some(hits) = result["hits"].as_array() {
                    for row in hits.iter().filter(|row| row["service_name"] == "nddev-device-sync-client") {
                        assert_eq!(row["service_device_id"], view.current_device_id);
                        assert_eq!(row["service_user_id"], view.user_id);
                        assert_eq!(row["service_tenant_id"], view.tenant_id);
                        assert_eq!(row["service_source_repository"], "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-desktop");
                        assert_eq!(row["operation_name"], "module.operation");
                        count += 1;
                    }
                }
            }
            if count >= 2 { break count; }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("actual native spans did not become searchable");
    identity.logout().await.unwrap();
    identity
        .store
        .device_store(&view.tenant_id, &view.user_id)
        .delete()
        .await
        .unwrap();
    std::fs::write(receipt.with_file_name("client-delivery-result.json"), json!({"trace_id":trace_id,"delivered_events":after.delivered,"delivered_spans":after.spans_delivered,"dropped":after.dropped+after.spans_dropped,"signed_gateway":"passed","incident_ack_replay_resolution":"passed","background_resume":"passed","actual_server_disconnect_reconnect":"passed","observed_delivery_failures":after.failures-before.failures,"feedback":"absent","searchable_logs":searchable_logs,"searchable_native_spans":native_count}).to_string()).unwrap();
    traces.shutdown();
    logger.shutdown();
}

async fn fixture_mode(receipt: &std::path::Path, fixture: &Value, mode: &str) {
    let control = std::path::Path::new(fixture["control_file"].as_str().unwrap());
    std::fs::write(control, serde_json::to_vec(&json!({"mode":mode})).unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let current = std::fs::read(receipt)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            if !control.exists()
                && current.is_some_and(|v| {
                    v["status"]
                        == if mode == "offline" {
                            "offline"
                        } else {
                            "running"
                        }
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the owned server fixture did not change its actual process state");
}
use std::time::{SystemTime, UNIX_EPOCH};
