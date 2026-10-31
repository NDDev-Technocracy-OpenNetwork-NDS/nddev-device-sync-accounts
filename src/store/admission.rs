//! Cross-process/tab ownership for identity mutations and credential creation.
//! A credential worker retains the lease through actual I/O completion even if
//! its waiting caller has timed out. Durable fences separately handle crashes.
use super::*;

pub(crate) struct OperationPermit {
    _local: OwnedSemaphorePermit,
    _lease: Arc<Lease>,
}

/// One remote-module endpoint owns this purpose lock, without holding identity admission.
pub(crate) struct RdsLease {
    _lease: Arc<Lease>,
}

pub(super) struct Lease {
    #[cfg(not(target_arch = "wasm32"))]
    _file: std::fs::File,
    #[cfg(target_arch = "wasm32")]
    id: String,
}

#[cfg(not(target_arch = "wasm32"))]
fn acquire_native(key: &str) -> Result<Lease, ClientError> {
    let root = crate::private_data_directory()?.join("identity");
    std::fs::create_dir_all(&root).map_err(|_| ClientError::CredentialStore)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ClientError::CredentialStore)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let path = root.join(format!("{key}.lock"));
    if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_file()) {
        return Err(ClientError::CredentialStore);
    }
    let file = options
        .open(path)
        .map_err(|_| ClientError::CredentialStore)?;
    if !file
        .metadata()
        .map_err(|_| ClientError::CredentialStore)?
        .is_file()
    {
        return Err(ClientError::CredentialStore);
    }
    file.try_lock().map_err(|_| ClientError::Busy)?;
    Ok(Lease { _file: file })
}

#[cfg(target_arch = "wasm32")]
mod web {
    use super::*;
    use wasm_bindgen::prelude::*;
    #[wasm_bindgen(module = "/src/browser_credentials.js")]
    extern "C" {
        #[wasm_bindgen(catch, js_name = acquireIdentity)]
        fn acquire_identity(id: &str, key: &str) -> Result<js_sys::Promise, JsValue>;
        #[wasm_bindgen(js_name = releaseIdentity)]
        fn release_identity(id: &str);
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            release_identity(&self.id);
        }
    }
    pub(super) async fn acquire(key: &str) -> Result<Arc<Lease>, ClientError> {
        // The RAII identity exists before awaiting acquisition, so cancellation
        // also releases an acquisition whose Promise has not yet resolved.
        let lease = Arc::new(Lease {
            id: Fence::new(FenceMode::Checking)?.generation,
        });
        let promise = acquire_identity(&lease.id, key).map_err(super::super::browser::failure)?;
        wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(super::super::browser::failure)?;
        Ok(lease)
    }
}

impl SessionStore {
    pub(crate) async fn rds_lease(&self) -> Result<RdsLease, ClientError> {
        if self.service != "ai.nddev.nds.rds.v1" {
            return Err(ClientError::InvalidInput);
        }
        #[cfg(not(target_arch = "wasm32"))]
        let lease = {
            let key = self.key.clone();
            tokio::time::timeout(
                Duration::from_secs(15),
                tokio::task::spawn_blocking(move || acquire_native(&key).map(Arc::new)),
            )
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::CredentialStore)??
        };
        #[cfg(target_arch = "wasm32")]
        let lease = web::acquire(&self.key).await?;
        Ok(RdsLease { _lease: lease })
    }

    pub(crate) async fn activate_operation(
        &self,
        local: OwnedSemaphorePermit,
    ) -> Result<OperationPermit, ClientError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let owner = self.owner.clone();
            self.run_io("identity.operation.admitted", move |_, key| {
                let lease = Arc::new(acquire_native(key)?);
                *owner.lease.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(&lease);
                Ok(OperationPermit {
                    _local: local,
                    _lease: lease,
                })
            })
            .await
        }
        #[cfg(target_arch = "wasm32")]
        {
            let key = self.key.clone();
            let owner = self.owner.clone();
            self.browser_io("identity.operation.admitted", async move {
                let lease = web::acquire(&key).await?;
                *owner.lease.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(&lease);
                Ok(OperationPermit {
                    _local: local,
                    _lease: lease,
                })
            })
            .await
        }
    }
}
