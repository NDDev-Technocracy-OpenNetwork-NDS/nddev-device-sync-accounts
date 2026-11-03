use super::*;
use nddev_device_sync_telemetry::{Config, ExportFeed};
use opentelemetry::trace::TracerProvider;
use std::io::{BufRead, Write};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("nds-native-spool-{}", uuid::Uuid::new_v4())))
    }
    fn queue(&self, scope: char) -> Arc<Queue> {
        Queue::open(self.0.clone(), scope.to_string().repeat(64)).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn feed(count: usize) -> ExportFeed {
    let config = Config {
        service: "nddev-device-sync-client".into(),
        version: "0.0.1-alpha.1".into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-desktop".into(),
        commit: "unknown".into(),
        channel: "alpha".into(),
        standards: "unreleased".into(),
        environment: "test".into(),
        target_prefixes: vec!["nds_spool_test".into()],
        default_module: "accounts".into(),
        debug: None,
    };
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::default();
    let (subscriber, control) = nddev_device_sync_telemetry::subscriber(
        config,
        std::io::sink(),
        provider.tracer("native-spool"),
    )
    .unwrap();
    let feed = control.subscribe().unwrap();
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..count {
            tracing::info!(target:"nds_spool_test",event.name="spool.fixture.record",outcome="ok");
        }
    });
    feed
}
async fn put(q: &Arc<Queue>, trace: bool, count: usize) -> Vec<u8> {
    let feed = feed(count);
    let batch = feed.take_batch().unwrap();
    let bytes = batch.bytes().to_vec();
    let (health, stored) = q.persist(trace, batch).await.map_err(|_| ()).unwrap();
    assert!(stored);
    assert_eq!(feed.health().pending, 0);
    assert_eq!(feed.health().dropped, 0);
    assert_eq!(feed.health().delivered, 0);
    assert!(health.events.pending + health.traces.pending >= count as u32);
    bytes
}
#[tokio::test]
async fn restart_keeps_exact_bytes_attempts_and_one_time_receipt() {
    let root = Root::new();
    let q = root.queue('a');
    let original = put(&q, false, 7).await;
    let b = q.next().await.unwrap().unwrap();
    assert_eq!(b.bytes, original);
    q.failed(&b).await.unwrap();
    drop(b);
    drop(q);
    let q = root.queue('a');
    let b = q.next().await.unwrap().unwrap();
    assert_eq!(b.bytes, original);
    assert_eq!(b.attempts, 1);
    assert!(q.finish(&b, Some(8)).await.is_err());
    assert_eq!(q.health().await.unwrap().events.pending, 7);
    let h = q.finish(&b, Some(7)).await.unwrap();
    assert_eq!(
        (h.events.pending, h.events.delivered, h.events.dropped),
        (0, 7, 0)
    );
    let h = q.finish(&b, Some(7)).await.unwrap();
    assert_eq!(h.events.delivered, 7);
    assert!(q.next().await.unwrap().is_none());
}
#[tokio::test]
async fn partial_trace_receipt_is_terminal_and_off_never_recounts_a_deleted_batch() {
    let root = Root::new();
    let q = root.queue('a');
    put(&q, true, 3).await;
    let b = q.next().await.unwrap().unwrap();
    let h = q.finish(&b, Some(1)).await.unwrap();
    assert_eq!(
        (
            h.traces.pending,
            h.traces.delivered,
            h.traces.dropped,
            h.last_success_at
        ),
        (0, 1, 2, 0)
    );
    assert!(q.next().await.unwrap().is_none());
    put(&q, false, 2).await;
    let b = q.next().await.unwrap().unwrap();
    let h = q.enabled(false).await.unwrap();
    assert_eq!((h.events.pending, h.events.dropped), (0, 2));
    let h = q.finish(&b, Some(2)).await.unwrap();
    assert_eq!((h.events.delivered, h.events.dropped), (0, 2));
    let ingress = feed(1);
    let (h, stored) = q
        .persist(false, ingress.take_batch().unwrap())
        .await
        .map_err(|_| ())
        .unwrap();
    assert!(!stored);
    assert_eq!(h.events.dropped, 3);
    assert_eq!(ingress.health().dropped, 0);
    q.enabled(true).await.unwrap();
    put(&q, false, 1).await;
    assert_eq!(q.health().await.unwrap().events.pending, 1);
}
#[tokio::test]
async fn scope_and_sender_ownership_are_enforced_by_real_locks_and_rows() {
    let root = Root::new();
    let a = root.queue('a');
    let b = root.queue('b');
    assert!(Queue::open(root.0.clone(), "a".repeat(64)).is_err());
    put(&a, false, 1).await;
    put(&b, false, 2).await;
    let first = a.next().await.unwrap().unwrap();
    let h = b.finish(&first, Some(1)).await.unwrap();
    assert_eq!((h.events.pending, h.events.delivered), (2, 0));
    assert_eq!(a.health().await.unwrap().events.pending, 1);
    a.finish(&first, Some(1)).await.unwrap();
    drop(a);
    assert!(Queue::open(root.0.clone(), "a".repeat(64)).is_ok());
}
#[tokio::test]
async fn expiry_is_counted_once_but_an_owned_late_receipt_can_still_settle() {
    let root = Root::new();
    let q = root.queue('a');
    put(&q, false, 2).await;
    put(&q, true, 3).await;
    let mut owned = q.next().await.unwrap().unwrap();
    q.run(|db, scope, now| {
        db.execute(
            "UPDATE batches SET expires=?1 WHERE scope=?2",
            params![now.saturating_sub(1), scope],
        )
    })
    .await
    .unwrap()
    .unwrap();
    let h = q.health().await.unwrap();
    assert_eq!(
        (
            h.events.pending,
            h.events.dropped,
            h.traces.pending,
            h.traces.dropped
        ),
        (2, 0, 0, 3)
    );
    owned.expires_at_ms = 0;
    assert!(q.expired(&owned));
    let h = q.finish(&owned, Some(2)).await.unwrap();
    assert_eq!(
        (h.events.delivered, h.events.dropped, h.traces.dropped),
        (2, 0, 3)
    );
    let h = q.health().await.unwrap();
    assert_eq!(h.traces.dropped, 3);
}
#[tokio::test]
async fn payload_and_record_pressure_do_not_erase_previously_committed_data() {
    let root = Root::new();
    let q = root.queue('a');
    q.run(|db,scope,now| {
        let tx=db.transaction().unwrap();
        for _ in 0..128 {tx.execute("INSERT INTO batches(scope,trace,count,payload,expires) VALUES(?1,0,1,zeroblob(65536),?2)",params![scope,now+1_800_000]).unwrap();}
        tx.commit().unwrap();
    }).await.unwrap();
    let ingress = feed(1);
    let (h, stored) = q
        .persist(false, ingress.take_batch().unwrap())
        .await
        .map_err(|_| ())
        .unwrap();
    assert!(!stored);
    assert_eq!((h.events.pending, h.events.dropped), (128, 1));
    q.enabled(false).await.unwrap();
    q.enabled(true).await.unwrap();
    q.run(|db, scope, now| {
        let tx = db.transaction().unwrap();
        for _ in 0..128 {
            tx.execute(
                "INSERT INTO batches(scope,trace,count,payload,expires) VALUES(?1,0,32,x'01',?2)",
                params![scope, now + 1_800_000],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    })
    .await
    .unwrap();
    let ingress = feed(1);
    let (h, stored) = q
        .persist(false, ingress.take_batch().unwrap())
        .await
        .map_err(|_| ())
        .unwrap();
    assert!(!stored);
    assert_eq!(h.events.pending, 4096);
    assert_eq!(h.events.dropped, 130);
}
#[tokio::test]
async fn actual_sqlite_full_keeps_the_original_ram_batch_until_a_payload_write_succeeds() {
    let root = Root::new();
    let q = root.queue('a');
    q.run(|db, _, _| {
        let pages: u32 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        db.pragma_update(None, "max_page_count", pages).unwrap();
    })
    .await
    .unwrap();
    let ingress = feed(32);
    let batch = ingress.take_batch().unwrap();
    let original = batch.bytes().to_vec();
    let returned = q
        .persist(false, batch)
        .await
        .err()
        .expect("real disk quota must refuse payload")
        .expect("uncommitted original batch remains owned");
    assert_eq!(returned.bytes(), original);
    assert_eq!(
        (ingress.health().pending, ingress.health().dropped),
        (32, 0)
    );
    q.run(|db, _, _| db.pragma_update(None, "max_page_count", 8192))
        .await
        .unwrap()
        .unwrap();
    let (_, stored) = q.persist(false, returned).await.map_err(|_| ()).unwrap();
    assert!(stored);
    assert_eq!(q.next().await.unwrap().unwrap().bytes, original);
    assert_eq!(ingress.health().pending, 0);
}
#[tokio::test]
async fn unknown_format_and_future_clock_leave_existing_bytes_untouched() {
    let root = Root::new();
    let q = root.queue('a');
    put(&q, false, 1).await;
    q.run(|db, scope, now| {
        db.execute(
            "UPDATE scopes SET observed_at=?1 WHERE scope=?2",
            params![now + 60_000, scope],
        )
    })
    .await
    .unwrap()
    .unwrap();
    drop(q);
    assert!(Queue::open(root.0.clone(), "a".repeat(64)).is_err());
    let db = Connection::open(root.0.join("exports.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM batches", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        1
    );
    db.pragma_update(None, "user_version", 99).unwrap();
    drop(db);
    assert!(Queue::open(root.0.clone(), "a".repeat(64)).is_err());
}
#[cfg(unix)]
#[test]
fn symlinked_roots_database_and_sender_are_refused_without_touching_targets() {
    use std::os::unix::fs::symlink;
    let root = Root::new();
    directory(&root.0).unwrap();
    let target = root.0.join("protected");
    fs::write(&target, b"KEEP_FOREIGN_FILE").unwrap();
    let alias = root.0.join("alias");
    symlink(&root.0, &alias).unwrap();
    assert!(Queue::open(alias, "a".repeat(64)).is_err());
    symlink(&target, root.0.join("exports.sqlite3")).unwrap();
    assert!(Queue::open(root.0.clone(), "a".repeat(64)).is_err());
    fs::remove_file(root.0.join("exports.sqlite3")).unwrap();
    directory(&root.0.join("senders")).unwrap();
    symlink(
        &target,
        root.0
            .join("senders")
            .join(format!("{}.lock", "a".repeat(64))),
    )
    .unwrap();
    assert!(Queue::open(root.0.clone(), "a".repeat(64)).is_err());
    assert_eq!(fs::read(target).unwrap(), b"KEEP_FOREIGN_FILE");
}
#[test]
fn scope_slots_are_bounded_without_reclaiming_unknown_or_live_owners() {
    let root = Root::new();
    let mut queues = Vec::new();
    for n in 0..MAX_SCOPES {
        queues.push(Queue::open(root.0.clone(), format!("{n:064x}")).unwrap());
    }
    assert!(Queue::open(root.0.clone(), format!("{:064x}", MAX_SCOPES)).is_err());
    assert_eq!(
        fs::read_dir(root.0.join("senders")).unwrap().count(),
        MAX_SCOPES as usize
    );
    drop(queues);
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
#[tokio::test]
async fn hard_kill_releases_sender_and_restart_reads_every_committed_batch() {
    let root = Root::new();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "telemetry::native_queue::tests::crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("NDS_SPOOL_CRASH_FIXTURE", &root.0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut child = Child(child);
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines().take(20) {
            if line.unwrap().contains("NDS_SPOOL_STAGED_96") {
                let _ = send.send(());
                return;
            }
        }
    });
    let ready = receive.recv_timeout(Duration::from_secs(30));
    if ready.is_err() {
        drop(child);
        reader.join().unwrap();
        panic!("child did not durably stage its real SDK feed");
    }
    assert!(Queue::open(root.0.clone(), "a".repeat(64)).is_err());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    reader.join().unwrap();
    let q = root.queue('a');
    let mut sequences = Vec::new();
    while let Some(b) = q.next().await.unwrap() {
        for line in b.bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let r: serde_json::Value = serde_json::from_slice(line).unwrap();
            sequences.push(r["producer.sequence"].as_u64().unwrap());
        }
        q.finish(&b, Some(i64::from(b.count))).await.unwrap();
    }
    assert_eq!(sequences, (1..=96).collect::<Vec<_>>());
    let h = q.health().await.unwrap();
    assert_eq!(
        (h.events.pending, h.events.delivered, h.events.dropped),
        (0, 96, 0)
    );
}
#[test]
#[ignore = "executed only in the owned hard-kill fixture subprocess"]
fn crash_child() {
    let root =
        PathBuf::from(std::env::var_os("NDS_SPOOL_CRASH_FIXTURE").expect("owned fixture path"));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async move {
        let q = Queue::open(root, "a".repeat(64)).unwrap();
        let feed = feed(96);
        while let Some(batch) = feed.take_batch() {
            assert!(q.persist(false, batch).await.map_err(|_| ()).unwrap().1);
        }
        assert_eq!(q.health().await.unwrap().events.pending, 96);
        println!("NDS_SPOOL_STAGED_96");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    });
}
