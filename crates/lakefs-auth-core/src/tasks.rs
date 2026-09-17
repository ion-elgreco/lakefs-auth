//! Supervision of background tasks that must run forever.
//!
//! A dropped `JoinHandle` hides a panic: the task dies, nothing logs it, and the
//! server keeps serving without the work the task did, such as refreshing the
//! identity provider keys or removing expired token ids. [`supervise`] keeps the
//! handle, logs every exit with the panic message, and starts the task again.

use std::any::Any;
use std::time::Duration;

use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;

const INITIAL_RESTART_DELAY: Duration = Duration::from_secs(1);
const MAX_RESTART_DELAY: Duration = Duration::from_secs(30);

/// Runs `factory()` as a task and restarts it whenever it ends.
///
/// Every supervised task is meant to loop forever, so a return and a panic are
/// both errors: each is logged and the task starts again after a delay that
/// doubles up to thirty seconds. A run that lasted longer than that resets the
/// delay. Aborting the returned handle also aborts the task it supervises.
pub fn supervise<F, Fut>(name: &'static str, factory: F) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut delay = INITIAL_RESTART_DELAY;
        loop {
            let started = Instant::now();
            let task = tokio::spawn(factory());
            let guard = AbortOnDrop(task.abort_handle());
            let outcome = task.await;
            drop(guard);
            match outcome {
                Ok(()) => tracing::error!(
                    task = name,
                    "background task returned although it runs forever; restarting"
                ),
                Err(error) if error.is_panic() => {
                    let message = panic_message(error.into_panic());
                    tracing::error!(task = name, panic = %message, "background task panicked; restarting");
                }
                // Cancelled: the runtime is shutting down, or this supervisor was aborted.
                Err(_) => return,
            }
            if started.elapsed() > MAX_RESTART_DELAY {
                delay = INITIAL_RESTART_DELAY;
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(MAX_RESTART_DELAY);
        }
    })
}

/// Aborts the supervised task when the supervisor itself is cancelled.
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A task that panics is restarted, and the panic is not swallowed silently.
    #[tokio::test(start_paused = true)]
    async fn a_panicking_task_is_restarted() {
        let runs = Arc::new(AtomicUsize::new(0));
        let (done, finished) = tokio::sync::oneshot::channel::<usize>();
        let done = Arc::new(std::sync::Mutex::new(Some(done)));
        let handle = supervise("test task", {
            let runs = Arc::clone(&runs);
            move || {
                let run = runs.fetch_add(1, Ordering::SeqCst) + 1;
                let done = Arc::clone(&done);
                async move {
                    if run == 1 {
                        panic!("first run dies");
                    }
                    if let Some(done) = done.lock().expect("lock").take() {
                        let _ = done.send(run);
                    }
                    std::future::pending::<()>().await;
                }
            }
        });
        let run = finished.await.expect("the second run reports in");
        assert_eq!(run, 2);
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        handle.abort();
    }

    /// A task that returns is also restarted, because every supervised task is
    /// meant to loop forever.
    #[tokio::test(start_paused = true)]
    async fn a_task_that_returns_is_restarted() {
        let runs = Arc::new(AtomicUsize::new(0));
        let (done, finished) = tokio::sync::oneshot::channel::<()>();
        let done = Arc::new(std::sync::Mutex::new(Some(done)));
        let handle = supervise("returning task", {
            let runs = Arc::clone(&runs);
            move || {
                let run = runs.fetch_add(1, Ordering::SeqCst) + 1;
                let done = Arc::clone(&done);
                async move {
                    if run >= 3 {
                        if let Some(done) = done.lock().expect("lock").take() {
                            let _ = done.send(());
                        }
                        std::future::pending::<()>().await;
                    }
                }
            }
        });
        finished.await.expect("the third run reports in");
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        handle.abort();
    }
}
