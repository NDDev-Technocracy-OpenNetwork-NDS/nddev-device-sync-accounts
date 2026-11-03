//! Signed-client process-crash acceptance against the existing owned fixtures.
//! Only loopback fixture credentials and private test receipts are consumed.
use super::*;
use std::{
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
};

struct Child {
    process: std::process::Child,
    messages: Option<mpsc::Receiver<&'static str>>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.process.try_wait().ok().flatten().is_none() {
            let _ = self.process.kill();
        }
        let _ = self.process.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
impl Child {
    fn start(mode: &str, output: &Path) -> Self {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "telemetry::acceptance::native_spool::child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NDS_NATIVE_SPOOL_CHILD_MODE", mode)
            .env("NDS_NATIVE_SPOOL_CHILD_OUTPUT", output)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = process.stdout.take().unwrap();
        let (send, receive) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout.take(2 * 1024 * 1024))
                .lines()
                .map_while(Result::ok)
            {
                for marker in [
                    "NDS_NATIVE_SPOOL_READY",
                    "NDS_NATIVE_SPOOL_STAGED",
                    "NDS_NATIVE_SPOOL_DRAINED",
                ] {
                    if line.ends_with(marker) {
                        let _ = send.send(marker);
                    }
                }
            }
        });
        Self {
            process,
            messages: Some(receive),
            reader: Some(reader),
        }
    }
    async fn marker(&mut self, wanted: &'static str) {
        let receive = self.messages.take().unwrap();
        let (receive, result) = tokio::task::spawn_blocking(move || {
            let result = receive.recv_timeout(Duration::from_secs(40));
            (receive, result)
        })
        .await
        .unwrap();
        self.messages = Some(receive);
        assert_eq!(result.unwrap(), wanted);
    }
    async fn exited(&mut self) {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(status) = self.process.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("owned restart child did not terminate");
    }
}
pub(super) async fn qualify(
    identity: &Arc<IdentityClient>,
    fixture: &Value,
    receipt: &Path,
    http: &reqwest::Client,
    query: &Value,
) -> Value {
    let stage_path =
        receipt.with_file_name(format!("native-spool-stage-{}.json", uuid::Uuid::new_v4()));
    let drain_path =
        receipt.with_file_name(format!("native-spool-drain-{}.json", uuid::Uuid::new_v4()));
    let original = identity.view();
    let mut stage = Child::start("stage", &stage_path);
    stage.marker("NDS_NATIVE_SPOOL_READY").await;
    fixture_mode(receipt, fixture, "offline").await;
    stage
        .process
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"S")
        .unwrap();
    stage.marker("NDS_NATIVE_SPOOL_STAGED").await;
    let staged: Value = serde_json::from_slice(&std::fs::read(&stage_path).unwrap()).unwrap();
    assert_eq!(staged["user_id"], original.user_id);
    assert_eq!(staged["tenant_id"], original.tenant_id);
    assert_eq!(staged["device_id"], original.current_device_id);
    assert!(staged["stored_events"].as_u64().unwrap() >= 96);
    assert!(staged["stored_spans"].as_u64().unwrap() >= 1);
    stage.process.kill().unwrap();
    let terminated = stage.process.wait().unwrap();
    assert!(!terminated.success());
    drop(stage);
    fixture_mode(receipt, fixture, "online").await;
    let mut drain = Child::start("drain", &drain_path);
    drain.marker("NDS_NATIVE_SPOOL_READY").await;
    drain.marker("NDS_NATIVE_SPOOL_DRAINED").await;
    drain.exited().await;
    drop(drain);
    let drained: Value = serde_json::from_slice(&std::fs::read(&drain_path).unwrap()).unwrap();
    assert_eq!(drained["device_id"], original.current_device_id);
    assert_eq!(drained["pending"], 0);
    assert_eq!(drained["dropped"], 0);
    let trace = staged["trace_id"].as_str().unwrap();
    assert!(trace.len() == 32 && trace.bytes().all(|b| b.is_ascii_hexdigit()));
    let origin = query["origin"].as_str().unwrap();
    assert!(origin.starts_with("http://127.0.0.1:"));
    let user = query["user"].as_str().unwrap();
    let password = query["password"].as_str().unwrap();
    let count=tokio::time::timeout(Duration::from_secs(25),async {
        loop {
            let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
            let body=json!({"query":{"sql":format!("SELECT * FROM nds WHERE trace_id='{trace}' AND event_name='native.spool.restart.record'"),"start_time":now-3_600_000_000u64,"end_time":now+2_000_000,"from":0,"size":200}});
            let found:Value=http.post(format!("{origin}/api/default/_search?type=logs")).basic_auth(user,Some(password)).json(&body).send().await.unwrap().json().await.unwrap();
            if let Some(hits)=found["hits"].as_array().filter(|hits|hits.len()>=96) {
                assert_eq!(hits.len(),96,"committed crash records were duplicated");
                for row in hits {assert_eq!(row["user_id"],original.user_id);assert_eq!(row["tenant_id"],original.tenant_id);assert_eq!(row["device_id"],original.current_device_id);}
                break hits.len();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("hard-killed native client records did not become searchable exactly once in this fixture");
    let streams: Value = http
        .get(format!("{origin}/api/default/streams?type=traces"))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let span_count=tokio::time::timeout(Duration::from_secs(25),async {
        loop {
            let mut count=0;
            for stream in streams["list"].as_array().unwrap() {
                let table=stream["name"].as_str().unwrap();
                assert!(!table.is_empty()&&table.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'));
                let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
                let body=json!({"query":{"sql":format!("SELECT * FROM \"{table}\" WHERE trace_id='{trace}'"),"start_time":now-3_600_000_000u64,"end_time":now+2_000_000,"from":0,"size":100}});
                let result:Value=http.post(format!("{origin}/api/default/_search?type=traces")).basic_auth(user,Some(password)).json(&body).send().await.unwrap().json().await.unwrap();
                for row in result["hits"].as_array().into_iter().flatten().filter(|r|r["service_name"]=="nddev-device-sync-client") {
                    assert_eq!(row["service_user_id"],original.user_id);assert_eq!(row["service_tenant_id"],original.tenant_id);assert_eq!(row["service_device_id"],original.current_device_id);
                    assert_eq!(row["operation_name"],"module.operation");count+=1;
                }
            }
            if count>0 {break count;}
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("hard-killed native client's retained OTLP span did not become searchable");
    identity.refresh().await.unwrap();
    json!({"hard_kill":"passed","restored_original_scope":"passed","secret_canary_before_disk":"absent","searchable_unique_events":count,"searchable_retained_spans":span_count,"stage_receipt":stage_path,"drain_receipt":drain_path})
}
fn emit(marker: &str) {
    println!("{marker}");
    std::io::stdout().flush().unwrap();
}
fn private_result(path: &Path, value: Value) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    serde_json::to_writer(&mut file, &value).unwrap();
    file.sync_all().unwrap();
}
#[test]
#[ignore = "executed only as an owned signed-client crash/restart subprocess"]
fn child() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(child_run());
}
async fn child_run() {
    // A killed or suspended parent cannot leave an unbounded fixture child,
    // including a native stdin read that the async runtime cannot cancel.
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(120)).await;
        std::process::exit(2);
    });
    let mode = std::env::var("NDS_NATIVE_SPOOL_CHILD_MODE").unwrap();
    assert!(mode == "stage" || mode == "drain");
    let output = PathBuf::from(std::env::var_os("NDS_NATIVE_SPOOL_CHILD_OUTPUT").unwrap());
    assert!(output.is_absolute() && !output.exists());
    let receipt = PathBuf::from(std::env::var_os("NDS_FIXTURE_RECEIPT").unwrap());
    let fixture: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(output.parent(), receipt.parent());
    assert!(!output.starts_with(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))));
    let endpoint = fixture["base_url"].as_str().unwrap();
    assert!(endpoint.starts_with("http://127.0.0.1:"));
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
    std::panic::set_hook(Box::new(|_| {
        eprintln!("owned native spool child assertion failed")
    }));
    let identity = Arc::new(IdentityClient::new(endpoint).unwrap());
    assert!(identity.refresh().await.unwrap().authenticated);
    let view = identity
        .prepare_device("Native delivery acceptance".into())
        .await
        .unwrap();
    emit("NDS_NATIVE_SPOOL_READY");
    if mode == "stage" {
        tokio::task::spawn_blocking(|| {
            let mut gate = [0];
            std::io::stdin().read_exact(&mut gate).unwrap();
            assert_eq!(gate, [b'S']);
        })
        .await
        .unwrap();
    }
    let delivery = Delivery::start(
        identity.clone(),
        logger.control.subscribe().unwrap(),
        traces.subscribe().unwrap(),
        true,
    );
    if mode == "stage" {
        tokio::time::timeout(Duration::from_secs(15), async {
            while delivery.snapshot().local_persistence_ready != Some(true) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let before = delivery.snapshot();
        let span = nddev_device_sync_telemetry::operation_span("accounts", "process").unwrap();
        let trace = nddev_device_sync_telemetry::trace_context(&span)
            .span()
            .span_context()
            .trace_id()
            .to_string();
        let canary = format!("NDS_SPOOL_PRIVATE_CANARY_{}", uuid::Uuid::new_v4());
        span.in_scope(|| {
            for index in 0..96 {
                if index==0 {
                    tracing::event!(target:"nds_accounts",tracing::Level::INFO,{event.name="native.spool.restart.record",module="accounts",outcome="ok",private_payload=canary.as_str()});
                } else {
                    tracing::event!(target:"nds_accounts",tracing::Level::INFO,{event.name="native.spool.restart.record",module="accounts",outcome="ok"});
                }
            }
        });
        drop(span);
        let scope = crate::telemetry::source::scope(&identity);
        let database = crate::private_data_directory()
            .unwrap()
            .join("telemetry/exports.sqlite3");
        let counts = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let db = rusqlite::Connection::open_with_flags(
                    &database,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
                )
                .unwrap();
                db.busy_timeout(Duration::from_secs(1)).unwrap();
                let events: u32 = db
                    .query_row(
                        "SELECT coalesce(sum(count),0) FROM batches WHERE scope=?1 AND trace=0",
                        [&scope],
                        |r| r.get(0),
                    )
                    .unwrap();
                let spans: u32 = db
                    .query_row(
                        "SELECT coalesce(sum(count),0) FROM batches WHERE scope=?1 AND trace=1",
                        [&scope],
                        |r| r.get(0),
                    )
                    .unwrap();
                let health = delivery.snapshot();
                if events >= 96
                    && spans >= 1
                    && !delivery.source.native_busy()
                    && health.pending == events
                    && health.spans_pending == spans
                {
                    assert_eq!(health.delivered, before.delivered);
                    assert_eq!(health.spans_delivered, before.spans_delivered);
                    assert_eq!(health.dropped + health.spans_dropped, 0);
                    let mut statement = db
                        .prepare("SELECT payload FROM batches WHERE scope=?1 LIMIT 4096")
                        .unwrap();
                    for row in statement
                        .query_map([&scope], |r| r.get::<_, Vec<u8>>(0))
                        .unwrap()
                    {
                        let bytes = row.unwrap();
                        assert!(
                            !bytes
                                .windows(canary.len())
                                .any(|part| part == canary.as_bytes()),
                            "secret canary reached durable spool"
                        );
                    }
                    break (events, spans);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect(
            "all native SDK batches did not reach durable storage during the actual server outage",
        );
        private_result(
            &output,
            json!({"trace_id":trace,"user_id":view.user_id,"tenant_id":view.tenant_id,"device_id":view.current_device_id,"stored_events":counts.0,"stored_spans":counts.1}),
        );
        emit("NDS_NATIVE_SPOOL_STAGED");
        std::future::pending::<()>().await;
    } else {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let h = delivery.flush().await;
                if h.initialized
                    && h.local_persistence_ready == Some(true)
                    && h.pending + h.spans_pending == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("restarted signed native sender did not drain its original spool");
        let health = delivery.snapshot();
        assert_eq!(health.dropped + health.spans_dropped, 0);
        private_result(
            &output,
            json!({"device_id":view.current_device_id,"pending":health.pending+health.spans_pending,"dropped":health.dropped+health.spans_dropped}),
        );
        emit("NDS_NATIVE_SPOOL_DRAINED");
        drop(delivery);
        traces.shutdown();
        logger.shutdown();
    }
}
