//! One process-owned native context. Secret Service callbacks must be serviced
//! even when no presentation event loop is running.
use crate::ClientError;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::{Semaphore, oneshot};

#[derive(Clone)]
struct Dispatcher {
    context: glib::MainContext,
    requests: Arc<Semaphore>,
}

static DISPATCHER: Mutex<Option<Dispatcher>> = Mutex::new(None);

fn dispatcher() -> Result<Dispatcher, ClientError> {
    let mut current = DISPATCHER
        .lock()
        .map_err(|_| ClientError::CredentialStore)?;
    if current.is_none() {
        let (ready, startup) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("nds-credentials".into())
            .spawn(move || {
                let context = glib::MainContext::new();
                let _ = context.with_thread_default(|| {
                    if ready.send(context.clone()).is_ok() {
                        glib::MainLoop::new(Some(&context), false).run();
                    }
                });
            })
            .map_err(|_| ClientError::CredentialStore)?;
        let context = startup
            .recv_timeout(std::time::Duration::from_secs(1))
            .map_err(|_| ClientError::CredentialStore)?;
        *current = Some(Dispatcher {
            context,
            requests: Arc::new(Semaphore::new(16)),
        });
    }
    current
        .as_ref()
        .cloned()
        .ok_or(ClientError::CredentialStore)
}

pub(in crate::store) fn spawn<T: Send + 'static>(
    action: impl FnOnce() -> Result<T, ClientError> + Send + 'static,
    deadline: Instant,
) -> Result<oneshot::Receiver<Result<T, ClientError>>, ClientError> {
    dispatcher()?.spawn(action, deadline)
}

impl Dispatcher {
    fn spawn<T: Send + 'static>(
        &self,
        action: impl FnOnce() -> Result<T, ClientError> + Send + 'static,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<Result<T, ClientError>>, ClientError> {
        let permit = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| ClientError::Busy)?;
        let (reply, result) = oneshot::channel();
        let mut work = Some((action, reply, permit));
        let source = glib::source::idle_source_new(
            Some("nds-credential-request"),
            glib::Priority::DEFAULT,
            move || {
                if let Some((action, reply, _permit)) = work.take() {
                    if reply.is_closed() {
                        return glib::ControlFlow::Break;
                    }
                    if Instant::now() >= deadline {
                        let _ = reply.send(Err(ClientError::Timeout));
                        return glib::ControlFlow::Break;
                    }
                    // Match spawn_blocking's panic boundary without unwinding into
                    // GLib. The receiver reports a closed worker on panic.
                    if let Ok(value) =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(action))
                    {
                        let _ = reply.send(value);
                    }
                }
                glib::ControlFlow::Break
            },
        );
        source.attach(Some(&self.context));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    struct OwnedDispatcher {
        io: Dispatcher,
        main_loop: glib::MainLoop,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl OwnedDispatcher {
        fn new() -> Self {
            let context = glib::MainContext::new();
            let main_loop = glib::MainLoop::new(Some(&context), false);
            let worker_context = context.clone();
            let worker_loop = main_loop.clone();
            let (ready, started) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::spawn(move || {
                worker_context
                    .with_thread_default(|| {
                        ready.send(()).unwrap();
                        worker_loop.run();
                    })
                    .unwrap();
            });
            started.recv_timeout(Duration::from_secs(1)).unwrap();
            Self {
                io: Dispatcher {
                    context,
                    requests: Arc::new(Semaphore::new(16)),
                },
                main_loop,
                thread: Some(thread),
            }
        }
    }
    impl Drop for OwnedDispatcher {
        fn drop(&mut self) {
            let main_loop = self.main_loop.clone();
            self.io.context.invoke(move || main_loop.quit());
            self.thread.take().unwrap().join().unwrap();
        }
    }

    #[test]
    fn saturated_dispatch_refuses_work_and_cancelled_or_expired_jobs_never_execute() {
        let runtime = OwnedDispatcher::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (started, ready) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let running = runtime
            .io
            .spawn(
                move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(())
                },
                deadline,
            )
            .unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut pending = Vec::new();
        for _ in 1..16 {
            let calls = calls.clone();
            pending.push(
                runtime
                    .io
                    .spawn(move || Ok(calls.fetch_add(1, Ordering::SeqCst)), deadline)
                    .unwrap(),
            );
        }
        assert!(matches!(
            runtime.io.spawn(|| Ok(()), deadline),
            Err(ClientError::Busy)
        ));
        drop(pending);
        release.send(()).unwrap();
        running.blocking_recv().unwrap().unwrap();
        loop {
            match runtime.io.spawn(|| Ok(()), deadline) {
                Ok(done) => {
                    done.blocking_recv().unwrap().unwrap();
                    break;
                }
                Err(ClientError::Busy) if Instant::now() < deadline => std::thread::yield_now(),
                other => panic!("Unexpected dispatch barrier result: {}", other.is_err()),
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let expired_calls = calls.clone();
        let expired = runtime
            .io
            .spawn(
                move || Ok(expired_calls.fetch_add(1, Ordering::SeqCst)),
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(
            expired.blocking_recv().unwrap(),
            Err(ClientError::Timeout)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn panicking_job_closes_its_reply_and_does_not_stop_native_dispatch() {
        let runtime = OwnedDispatcher::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let failed = runtime
            .io
            .spawn::<()>(|| panic!("owned synthetic native job"), deadline)
            .unwrap();
        assert!(failed.blocking_recv().is_err());
        assert_eq!(
            runtime
                .io
                .spawn(|| Ok(7), deadline)
                .unwrap()
                .blocking_recv()
                .unwrap()
                .unwrap(),
            7
        );
    }
}
