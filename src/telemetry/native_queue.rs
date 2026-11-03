//! Native durable export storage, using the existing Accounts private-data owner.
//! One OS scope lock and owned blocking operations survive asynchronous caller loss.
//! Payloads are already redacted SDK bytes, never credentials or private keys.
use nddev_device_sync_telemetry::{ExportBatch, FeedHealth};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const APPLICATION_ID: u32 = 0x4e445354;
const MAX_COUNTER: u64 = super::source::MAX_COUNTER;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECORDS: u32 = 4096;
const MAX_SCOPES: u32 = 16;

#[derive(Clone, Copy)]
pub(super) enum Loss {
    Expired,
    Capacity,
    Off,
    RetryLimit,
    ReceiverRejected,
    Discarded,
}
impl Loss {
    pub const ALL: [Self; 6] = [
        Self::Expired,
        Self::Capacity,
        Self::Off,
        Self::RetryLimit,
        Self::ReceiverRejected,
        Self::Discarded,
    ];
    pub fn code(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Capacity => "capacity_exhausted",
            Self::Off => "disabled",
            Self::RetryLimit => "retry_exhausted",
            Self::ReceiverRejected => "receiver_rejected",
            Self::Discarded => "discarded",
        }
    }
    fn column(self) -> &'static str {
        match self {
            Self::Expired => "loss_expired",
            Self::Capacity => "loss_capacity",
            Self::Off => "loss_off",
            Self::RetryLimit => "loss_retry",
            Self::ReceiverRejected => "loss_rejected",
            Self::Discarded => "loss_discarded",
        }
    }
}
#[derive(Clone, Default)]
pub(super) struct Health {
    pub events: FeedHealth,
    pub traces: FeedHealth,
    pub last_success_at: u64,
    pub revision: u64,
    pub losses: [u64; 6],
}
pub(super) struct Batch {
    pub id: i64,
    pub trace: bool,
    pub count: u32,
    pub bytes: Vec<u8>,
    pub expires_at_ms: u64,
    pub attempts: u32,
}
pub(super) struct Queue {
    db: Mutex<Connection>,
    io: Arc<Semaphore>,
    scope: String,
    started: Instant,
    start_ms: u64,
    _sender: File,
    senders: PathBuf,
}
fn now_ms() -> Result<u64, ()> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis(),
    )
    .ok()
    .filter(|n| *n <= MAX_COUNTER)
    .ok_or(())
}
fn directory(path: &Path) -> Result<(), ()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && !meta.file_type().is_dir()
    {
        return Err(());
    }
    fs::create_dir_all(path).map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
    }
    Ok(())
}
fn private_file(path: &Path, create: bool) -> Result<File, ()> {
    if fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_file()) {
        return Err(());
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| ())?;
    if !file.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| ())?;
    }
    Ok(file)
}
impl Queue {
    pub fn open(root: PathBuf, scope: String) -> Result<Arc<Self>, ()> {
        if !root.is_absolute()
            || scope.len() != 64
            || !scope
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(());
        }
        directory(&root)?;
        let root = fs::canonicalize(root).map_err(|_| ())?;
        let path = root.join("exports.sqlite3");
        let _file = private_file(&path, true)?;
        let mut db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| ())?;
        db.busy_timeout(Duration::from_millis(500))
            .map_err(|_| ())?;
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA max_page_count=8192;").map_err(|_| ())?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ())?;
        let version: u32 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|_| ())?;
        let application: u32 = tx
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(|_| ())?;
        if version == 0 && application == 0 {
            let tables: u32 = tx
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| ())?;
            if tables != 0 {
                return Err(());
            }
            tx.execute_batch("CREATE TABLE scopes(
                scope TEXT PRIMARY KEY CHECK(length(scope)=64),
                enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
                delivered_events INTEGER NOT NULL DEFAULT 0 CHECK(delivered_events BETWEEN 0 AND 9007199254740991),
                delivered_traces INTEGER NOT NULL DEFAULT 0 CHECK(delivered_traces BETWEEN 0 AND 9007199254740991),
                dropped_events INTEGER NOT NULL DEFAULT 0 CHECK(dropped_events BETWEEN 0 AND 9007199254740991),
                dropped_traces INTEGER NOT NULL DEFAULT 0 CHECK(dropped_traces BETWEEN 0 AND 9007199254740991),
                failures_events INTEGER NOT NULL DEFAULT 0 CHECK(failures_events BETWEEN 0 AND 9007199254740991),
                failures_traces INTEGER NOT NULL DEFAULT 0 CHECK(failures_traces BETWEEN 0 AND 9007199254740991),
                loss_expired INTEGER NOT NULL DEFAULT 0 CHECK(loss_expired BETWEEN 0 AND 9007199254740991),
                loss_capacity INTEGER NOT NULL DEFAULT 0 CHECK(loss_capacity BETWEEN 0 AND 9007199254740991),
                loss_off INTEGER NOT NULL DEFAULT 0 CHECK(loss_off BETWEEN 0 AND 9007199254740991),
                loss_retry INTEGER NOT NULL DEFAULT 0 CHECK(loss_retry BETWEEN 0 AND 9007199254740991),
                loss_rejected INTEGER NOT NULL DEFAULT 0 CHECK(loss_rejected BETWEEN 0 AND 9007199254740991),
                loss_discarded INTEGER NOT NULL DEFAULT 0 CHECK(loss_discarded BETWEEN 0 AND 9007199254740991),
                last_success INTEGER NOT NULL DEFAULT 0 CHECK(last_success>=0),
                observed_at INTEGER NOT NULL CHECK(observed_at BETWEEN 0 AND 9007199254740991),
                revision INTEGER NOT NULL DEFAULT 0 CHECK(revision BETWEEN 0 AND 9007199254740991));
                CREATE TABLE batches(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL REFERENCES scopes(scope),
                trace INTEGER NOT NULL CHECK(trace IN(0,1)),
                count INTEGER NOT NULL CHECK(count BETWEEN 1 AND 32),
                payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 65536),
                expires INTEGER NOT NULL CHECK(expires BETWEEN 0 AND 9007199254740991),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
                claimed INTEGER NOT NULL DEFAULT 0 CHECK(claimed IN(0,1)));
                CREATE INDEX batches_scope_order ON batches(scope,id);
                PRAGMA user_version=1;").map_err(|_| ())?;
            tx.pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(|_| ())?;
        } else if version != 1 || application != APPLICATION_ID {
            return Err(());
        }
        let now = now_ms()?;
        let previous: Option<u64> = tx
            .query_row(
                "SELECT observed_at FROM scopes WHERE scope=?1",
                [&scope],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| ())?;
        if previous.is_some_and(|n| n > now) {
            return Err(());
        }
        if previous.is_none() {
            let count: u32 = tx
                .query_row("SELECT count(*) FROM scopes", [], |r| r.get(0))
                .map_err(|_| ())?;
            if count >= MAX_SCOPES {
                return Err(());
            }
            tx.execute(
                "INSERT INTO scopes(scope,enabled,observed_at) VALUES(?1,1,?2)",
                params![scope, now],
            )
            .map_err(|_| ())?;
        }
        // Reserve only bounded scope names. Never unlink a lock inode: that
        // would allow two processes to own different files for the same scope.
        let senders = root.join("senders");
        directory(&senders)?;
        let sender = private_file(&senders.join(format!("{scope}.lock")), previous.is_none())?;
        sender.try_lock().map_err(|_| ())?;
        // The OS lease proves the previous owner and its storage operations
        // have ended. Retained attempts/bytes/expiry keep their original values.
        tx.execute("UPDATE batches SET claimed=0 WHERE scope=?1", [&scope])
            .map_err(|_| ())?;
        let leases = expire_other_scopes(&tx, &senders, &scope, now)?;
        tx.commit().map_err(|_| ())?;
        drop(leases);
        Ok(Arc::new(Self {
            db: Mutex::new(db),
            io: Arc::new(Semaphore::new(1)),
            scope,
            started: Instant::now(),
            start_ms: now,
            _sender: sender,
            senders,
        }))
    }
    fn clock(&self) -> Result<u64, ()> {
        self.start_ms
            .checked_add(
                self.started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .map_err(|_| ())?,
            )
            .map(|n| n.max(now_ms().unwrap_or(n)))
            .filter(|n| *n <= MAX_COUNTER)
            .ok_or(())
    }
    async fn run<R: Send + 'static>(
        self: &Arc<Self>,
        action: impl FnOnce(&mut Connection, &str, u64) -> R + Send + 'static,
    ) -> Result<R, ()> {
        let permit = self.io.clone().acquire_owned().await.map_err(|_| ())?;
        let queue = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let now = queue.clock()?;
            let mut db = queue.db.lock().map_err(|_| ())?;
            Ok(action(&mut db, &queue.scope, now))
        })
        .await
        .map_err(|_| ())?
    }
    pub fn expired(&self, batch: &Batch) -> bool {
        self.clock().map_or(true, |now| now >= batch.expires_at_ms)
    }
    pub async fn health(self: &Arc<Self>) -> Result<Health, ()> {
        let senders = self.senders.clone();
        self.run(move |db, scope, now| {
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| ())?;
            let leases = expire_other_scopes(&tx, &senders, scope, now)?;
            expire(&tx, scope, now, false)?;
            touch(&tx, scope, now)?;
            let health = snapshot(&tx, scope)?;
            tx.commit().map_err(|_| ())?;
            drop(leases);
            Ok(health)
        })
        .await?
    }
    pub async fn persist(
        self: &Arc<Self>,
        trace: bool,
        batch: ExportBatch,
    ) -> Result<(Health, bool), Option<ExportBatch>> {
        let senders = self.senders.clone();
        self.run(move |db,scope,now| {
            let commit = (|| {
                let expiry = if batch.expired() { 0 } else { batch.expires_at_ms().map_err(|_| ())? };
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|_| ())?;
                let leases = expire_other_scopes(&tx, &senders, scope, now)?;
                expire(&tx,scope,now,false)?;
                let enabled: bool = tx.query_row("SELECT enabled FROM scopes WHERE scope=?1",[scope],|r|r.get(0)).map_err(|_| ())?;
                let (bytes,records):(u64,u32) = tx.query_row("SELECT coalesce(sum(length(payload)),0),coalesce(sum(count),0) FROM batches",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_| ())?;
                let stored = enabled && expiry>now && bytes+batch.bytes().len() as u64<=MAX_BYTES && records+batch.count()<=MAX_RECORDS;
                if stored {
                    tx.execute("INSERT INTO batches(scope,trace,count,payload,expires) VALUES(?1,?2,?3,?4,?5)",params![scope,trace,batch.count(),batch.bytes(),expiry]).map_err(|_| ())?;
                } else {
                    let reason = if !enabled {Loss::Off} else if expiry<=now {Loss::Expired} else {Loss::Capacity};
                    loss(&tx,scope,trace,reason,u64::from(batch.count()))?;
                }
                touch(&tx,scope,now)?;
                tx.commit().map_err(|_| ())?;
                drop(leases);
                Ok(stored)
            })();
            match commit {
                Err(()) => Err(Some(batch)),
                Ok(stored) => {
                    // No fallible local operation can return this batch to RAM
                    // after the commit. An unreadable health result stays unknown.
                    batch.persisted();
                    snapshot(db,scope).map(|h|(h,stored)).map_err(|_| None)
                }
            }
        }).await.map_err(|_| None)?
    }
    pub async fn next(self: &Arc<Self>) -> Result<Option<Batch>, ()> {
        self.run(|db,scope,now| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|_| ())?;
            expire(&tx,scope,now,false)?;
            let batch = tx.query_row("SELECT id,trace,count,payload,expires,attempts FROM batches WHERE scope=?1 AND claimed=0 ORDER BY id LIMIT 1",[scope],|r|Ok(Batch{id:r.get(0)?,trace:r.get(1)?,count:r.get(2)?,bytes:r.get(3)?,expires_at_ms:r.get(4)?,attempts:r.get(5)?})).optional().map_err(|_| ())?;
            if let Some(batch) = &batch {
                if !(1..=32).contains(&batch.count) || batch.bytes.is_empty() || batch.bytes.len()>65536 || batch.attempts>8 {return Err(());}
                tx.execute("UPDATE batches SET claimed=1 WHERE id=?1 AND scope=?2",params![batch.id,scope]).map_err(|_| ())?;
            }
            touch(&tx,scope,now)?;
            tx.commit().map_err(|_| ())?;
            Ok(batch)
        }).await?
    }
    pub async fn enabled(self: &Arc<Self>, enabled: bool) -> Result<Health, ()> {
        self.run(move |db,scope,now| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|_| ())?;
            if !enabled {
                for trace in [false,true] {
                    let count: u64=tx.query_row("SELECT coalesce(sum(count),0) FROM batches WHERE scope=?1 AND trace=?2",params![scope,trace],|r|r.get(0)).map_err(|_| ())?;
                    loss(&tx,scope,trace,Loss::Off,count)?;
                }
                tx.execute("DELETE FROM batches WHERE scope=?1",[scope]).map_err(|_| ())?;
            }
            tx.execute("UPDATE scopes SET enabled=?1 WHERE scope=?2",params![enabled,scope]).map_err(|_| ())?;
            touch(&tx,scope,now)?;
            let h=snapshot(&tx,scope)?;
            tx.commit().map_err(|_| ())?;Ok(h)
        }).await?
    }
    pub async fn finish(
        self: &Arc<Self>,
        batch: &Batch,
        accepted: Option<i64>,
    ) -> Result<Health, ()> {
        let id = batch.id;
        let trace = batch.trace;
        let count = batch.count;
        if accepted.is_some_and(|n| n < 0 || n > i64::from(count)) {
            return Err(());
        }
        self.run(move |db, scope, now| {
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| ())?;
            let original: Option<(bool, u32, u64, u32)> = tx
                .query_row(
                    "SELECT trace,count,expires,attempts FROM batches WHERE id=?1 AND scope=?2",
                    params![id, scope],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()
                .map_err(|_| ())?;
            if let Some((original_trace, original_count, expiry, attempts)) = original {
                if (original_trace, original_count) != (trace, count) {
                    return Err(());
                }
                let delivered = accepted.unwrap_or(0) as u64;
                counter(&tx, scope, trace, "delivered", delivered)?;
                let reason = if accepted.is_some() {
                    Loss::ReceiverRejected
                } else if expiry <= now {
                    Loss::Expired
                } else if attempts >= 8 {
                    Loss::RetryLimit
                } else {
                    Loss::Discarded
                };
                loss(&tx, scope, trace, reason, u64::from(count) - delivered)?;
                if accepted == Some(i64::from(count)) {
                    tx.execute(
                        "UPDATE scopes SET last_success=?1 WHERE scope=?2",
                        params![now / 1000, scope],
                    )
                    .map_err(|_| ())?;
                }
                tx.execute(
                    "DELETE FROM batches WHERE id=?1 AND scope=?2",
                    params![id, scope],
                )
                .map_err(|_| ())?;
                touch(&tx, scope, now)?;
            }
            let health = snapshot(&tx, scope)?;
            tx.commit().map_err(|_| ())?;
            Ok(health)
        })
        .await?
    }
    pub async fn failed(self: &Arc<Self>, batch: &Batch) -> Result<Health, ()> {
        let id = batch.id;
        let trace = batch.trace;
        self.run(move |db, scope, now| {
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| ())?;
            let changed = tx
                .execute(
                    "UPDATE batches SET attempts=min(attempts+1,8) WHERE id=?1 AND scope=?2",
                    params![id, scope],
                )
                .map_err(|_| ())?;
            if changed != 1 {
                return Err(());
            }
            counter(&tx, scope, trace, "failures", 1)?;
            touch(&tx, scope, now)?;
            let h = snapshot(&tx, scope)?;
            tx.commit().map_err(|_| ())?;
            Ok(h)
        })
        .await?
    }
}
fn counter(db: &Connection, scope: &str, trace: bool, kind: &str, count: u64) -> Result<(), ()> {
    let signal = if trace { "traces" } else { "events" };
    let name = match kind {
        "delivered" | "dropped" | "failures" => format!("{kind}_{signal}"),
        _ => return Err(()),
    };
    db.execute(
        &format!("UPDATE scopes SET {name}=min({name}+?1,9007199254740991) WHERE scope=?2"),
        params![count, scope],
    )
    .map_err(|_| ())?;
    Ok(())
}
fn loss(db: &Connection, scope: &str, trace: bool, reason: Loss, count: u64) -> Result<(), ()> {
    counter(db, scope, trace, "dropped", count)?;
    let column = reason.column();
    db.execute(
        &format!("UPDATE scopes SET {column}=min({column}+?1,9007199254740991) WHERE scope=?2"),
        params![count, scope],
    )
    .map_err(|_| ())?;
    Ok(())
}
fn touch(db: &Connection, scope: &str, now: u64) -> Result<(), ()> {
    let changed=db.execute("UPDATE scopes SET observed_at=max(observed_at,?1),revision=revision+1 WHERE scope=?2 AND revision<9007199254740991",params![now,scope]).map_err(|_| ())?;
    if changed == 1 { Ok(()) } else { Err(()) }
}
fn expire(db: &Transaction<'_>, scope: &str, now: u64, include_claimed: bool) -> Result<bool, ()> {
    for trace in [false, true] {
        let count:u64=db.query_row("SELECT coalesce(sum(count),0) FROM batches WHERE scope=?1 AND trace=?2 AND (claimed=0 OR ?4) AND expires<=?3",params![scope,trace,now,include_claimed],|r|r.get(0)).map_err(|_| ())?;
        loss(db, scope, trace, Loss::Expired, count)?;
    }
    let removed = db
        .execute(
            "DELETE FROM batches WHERE scope=?1 AND (claimed=0 OR ?3) AND expires<=?2",
            params![scope, now, include_claimed],
        )
        .map_err(|_| ())?;
    Ok(removed != 0)
}
// Reclaim expired payloads from an inactive original scope only after its
// stable OS lock proves that no old process or detached storage I/O owns it.
// Keep scope counters and lock inodes; the same finite 16-scope bound applies.
fn expire_other_scopes(
    db: &Transaction<'_>,
    senders: &Path,
    current: &str,
    now: u64,
) -> Result<Vec<File>, ()> {
    let mut statement = db
        .prepare("SELECT scope,observed_at FROM scopes WHERE scope<>?1 LIMIT 17")
        .map_err(|_| ())?;
    let scopes = statement
        .query_map([current], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
        })
        .map_err(|_| ())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    if scopes.len() >= MAX_SCOPES as usize {
        return Err(());
    }
    let mut leases = Vec::new();
    for (scope, observed) in scopes {
        if scope.len() != 64
            || !scope
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(());
        }
        if observed > now {
            continue;
        }
        let Ok(file) = private_file(&senders.join(format!("{scope}.lock")), false) else {
            continue;
        };
        if file.try_lock().is_err() {
            continue;
        }
        if expire(db, &scope, now, true)? {
            touch(db, &scope, now)?;
        }
        leases.push(file);
    }
    Ok(leases)
}
fn snapshot(db: &Connection, scope: &str) -> Result<Health, ()> {
    let mut h=db.query_row("SELECT delivered_events,delivered_traces,dropped_events,dropped_traces,failures_events,failures_traces,last_success,revision,loss_expired,loss_capacity,loss_off,loss_retry,loss_rejected,loss_discarded FROM scopes WHERE scope=?1",[scope],|r|Ok(Health{events:FeedHealth{delivered:r.get(0)?,dropped:r.get(2)?,failures:r.get(4)?,..Default::default()},traces:FeedHealth{delivered:r.get(1)?,dropped:r.get(3)?,failures:r.get(5)?,..Default::default()},last_success_at:r.get(6)?,revision:r.get(7)?,losses:[r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?]})).map_err(|_| ())?;
    for trace in [false, true] {
        let count: u32 = db
            .query_row(
                "SELECT coalesce(sum(count),0) FROM batches WHERE scope=?1 AND trace=?2",
                params![scope, trace],
                |r| r.get(0),
            )
            .map_err(|_| ())?;
        if trace {
            h.traces.pending = count;
        } else {
            h.events.pending = count;
        }
    }
    Ok(h)
}

#[cfg(test)]
pub(super) mod tests;
