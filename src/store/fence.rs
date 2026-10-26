//! Durable authorization generation only: no token, key or grant payload lives
//! in this metadata. It prevents a late external key-store write from restoring
//! an older grant after another process has locked or revoked local access.
use super::*;
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 1;

/// Native authorization-fence format enforced by this implementation.
/// This reads no credentials or database and grants no schema transition.
pub const fn authorization_fence_schema_version() -> u32 {
    SCHEMA_VERSION
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FenceMode {
    Checking,
    Denied,
    Ready,
    SignedOut,
    PendingLogout,
}

impl FenceMode {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Checking => "checking",
            Self::Denied => "denied",
            Self::Ready => "ready",
            Self::SignedOut => "signed_out",
            Self::PendingLogout => "pending_logout",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fence {
    pub generation: String,
    pub slot: u8,
    pub mode: FenceMode,
}

impl Fence {
    pub(crate) fn new(mode: FenceMode) -> Result<Self, ClientError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| ClientError::CredentialStore)?;
        Ok(Self {
            generation: URL_SAFE_NO_PAD.encode(bytes),
            slot: 0,
            mode,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
    use std::path::Path;

    fn connection(path: &Path) -> Result<Connection, ClientError> {
        let failed = |_| ClientError::CredentialStore;
        let parent = path.parent().ok_or(ClientError::CredentialStore)?;
        std::fs::create_dir_all(parent).map_err(failed)?;
        // macOS system roots may be aliases (/var -> /private/var). Resolve
        // the directory while preserving NOFOLLOW for the database itself.
        let path = std::fs::canonicalize(parent)
            .map_err(failed)?
            .join(path.file_name().ok_or(ClientError::CredentialStore)?);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(failed)?;
        }
        let db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| ClientError::CredentialStore)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(failed)?;
        }
        db.busy_timeout(Duration::from_millis(500))
            .map_err(|_| ClientError::Busy)?;
        db.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA max_page_count=64;",
        )
        .map_err(|_| ClientError::CredentialStore)?;
        let version: u32 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|_| ClientError::CredentialStore)?;
        if version == 0 {
            let count: u32 = db
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| ClientError::CredentialStore)?;
            if count != 0 {
                return Err(ClientError::CredentialStore);
            }
            db.execute_batch(&format!("BEGIN IMMEDIATE; CREATE TABLE authorization(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation TEXT NOT NULL CHECK(length(generation)=43),mode TEXT NOT NULL CHECK(mode IN ('checking','denied','ready','signed_out','pending_logout')),slot INTEGER NOT NULL CHECK(slot IN (0,1))); PRAGMA user_version={SCHEMA_VERSION}; COMMIT;")).map_err(|_| ClientError::CredentialStore)?;
        } else if version != SCHEMA_VERSION {
            return Err(ClientError::CredentialStore);
        }
        Ok(db)
    }

    fn read(db: &Connection) -> Result<Option<Fence>, ClientError> {
        let row: Option<(String, String, u8)> = db
            .query_row(
                "SELECT generation,mode,slot FROM authorization WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| ClientError::CredentialStore)?;
        row.map(|(generation, mode, slot)| {
            if generation.len() != 43
                || !generation
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            {
                return Err(ClientError::CredentialStore);
            }
            let mode = match mode.as_str() {
                "checking" => FenceMode::Checking,
                "denied" => FenceMode::Denied,
                "ready" => FenceMode::Ready,
                "signed_out" => FenceMode::SignedOut,
                "pending_logout" => FenceMode::PendingLogout,
                _ => return Err(ClientError::CredentialStore),
            };
            Ok(Fence {
                generation,
                slot,
                mode,
            })
        })
        .transpose()
    }

    pub(super) fn operate(
        path: &Path,
        change: Option<(Option<Fence>, Fence)>,
    ) -> Result<Option<Fence>, ClientError> {
        let mut db = connection(path)?;
        let Some((expected, next)) = change else {
            return read(&db);
        };
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ClientError::Busy)?;
        let current = read(&tx)?;
        if current != expected {
            return Err(ClientError::Busy);
        }
        tx.execute("INSERT INTO authorization VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET generation=EXCLUDED.generation,mode=EXCLUDED.mode,slot=EXCLUDED.slot", rusqlite::params![next.generation,next.mode.as_str(),next.slot]).map_err(|_| ClientError::CredentialStore)?;
        tx.commit().map_err(|_| ClientError::CredentialStore)?;
        Ok(Some(next))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn actual_sqlite_fence_rejects_a_stale_completion_after_sign_out() {
            let path =
                std::env::temp_dir().join(format!("nds-owned-fence-{}", uuid::Uuid::new_v4()));
            let db = path.join("authorization.db");
            let first = Fence::new(FenceMode::Checking).unwrap();
            assert!(operate(&db, Some((None, first.clone()))).is_ok());
            let signed_out = Fence::new(FenceMode::SignedOut).unwrap();
            operate(&db, Some((Some(first.clone()), signed_out.clone()))).unwrap();
            let late = Fence {
                mode: FenceMode::Ready,
                ..first.clone()
            };
            assert_eq!(
                operate(&db, Some((Some(first), late))).err(),
                Some(ClientError::Busy)
            );
            assert!(operate(&db, None).unwrap() == Some(signed_out));
            std::fs::remove_dir_all(path).unwrap();
        }
        #[cfg(unix)]
        #[test]
        fn directory_alias_is_supported_but_database_symlinks_are_refused() {
            let root = std::env::temp_dir()
                .join(format!("nds-owned-fence-alias-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();
            let path = root.join("alias/authorization.db");
            operate(
                &path,
                Some((None, Fence::new(FenceMode::SignedOut).unwrap())),
            )
            .unwrap();
            std::fs::rename(&path, root.join("real/original.db")).unwrap();
            std::os::unix::fs::symlink(root.join("real/original.db"), &path).unwrap();
            assert_eq!(
                operate(&path, None).err(),
                Some(ClientError::CredentialStore)
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

impl SessionStore {
    pub(crate) async fn authorization_fence(
        &self,
        change: Option<(Option<Fence>, Fence)>,
    ) -> Result<Option<Fence>, ClientError> {
        let event = if change.is_some() {
            "identity.offline.fence"
        } else {
            "identity.offline.fence.read"
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.run_io(event, move |_, key| {
                let path = crate::private_data_directory()?
                    .join("identity")
                    .join(format!("{key}.db"));
                native::operate(&path, change)
            })
            .await
        }
        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::prelude::*;
            #[wasm_bindgen(module = "/src/browser_credentials.js")]
            extern "C" {
                #[wasm_bindgen(catch, js_name = authorizationFence)]
                fn fence(key: &str, change: &str) -> Result<js_sys::Promise, JsValue>;
            }
            let change =
                serde_json::to_string(&change).map_err(|_| ClientError::CredentialStore)?;
            let key = self.key.clone();
            self.browser_io(event, async move {
                let promise = fence(&key, &change).map_err(super::browser::failure)?;
                let output = wasm_bindgen_futures::JsFuture::from(promise)
                    .await
                    .map_err(super::browser::failure)?;
                let output = output
                    .as_string()
                    .filter(|s| s.len() <= 256)
                    .ok_or(ClientError::CredentialStore)?;
                serde_json::from_str(&output).map_err(|_| ClientError::CredentialStore)
            })
            .await
        }
    }
}
