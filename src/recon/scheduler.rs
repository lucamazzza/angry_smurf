//! A simple scheduler that executes jobs with a base delay and random jitter.

use std::{future::Future, sync::Arc, time::Duration};

use rand::{rngs::ThreadRng, Rng};
use tokio::{sync::Semaphore, time::sleep};

/// Configuration for the scheduler, including base delay, jitter, and maximum inflight jobs.
/// This configuration allows for controlling the execution rate of jobs, adding randomness to
/// avoid synchronized execution, and limiting the number of concurrent jobs.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub base_delay_ms: u64,
    pub jitter_ms: u64,
    pub max_inflight: usize,
}

impl SchedulerConfig {
    /// Creates a new `SchedulerConfig` with the specified base delay, jitter, and maximum inflight
    /// jobs.
    pub fn new(base_delay_ms: u64, jitter_ms: u64, max_inflight: usize) -> Self {
        Self {
            base_delay_ms,
            jitter_ms,
            max_inflight: max_inflight.max(1),
        }
    }
}

/// Schedules jobs to be executed with a base delay and random jitter.
/// The function takes an iterable of items, a configuration for the scheduler,
/// and a function to create jobs from the items.
/// Each job is executed asynchronously, respecting the maximum number of concurrent jobs
/// defined in the configuration.
/// The function ensures that jobs are executed with a base delay and adds a random jitter
/// to the execution time to avoid synchronized execution.
pub async fn schedule<T, F, Fut>(items: impl IntoIterator<Item = T>, cfg: SchedulerConfig, mut make_job: F) 
where 
    T: Send + 'static,
    F: FnMut(T) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let sem = Arc::new(Semaphore::new(cfg.max_inflight));
    let mut handles = Vec::new();
    let mut rng = rand::thread_rng();
    for item in items {
        let permit = sem.clone().acquire_owned().await.expect("Semaphore closed");
        let jitter = rand_jitter_ms(&mut rng, cfg.jitter_ms);
        let base_delay = cfg.base_delay_ms;
        let make_job_ref = &mut make_job;
        if base_delay > 0 {
            sleep(Duration::from_millis(base_delay)).await;
        }
        let fut = make_job_ref(item);
        let handle = tokio::spawn(async move {
            if jitter != 0 {
                let d = Duration::from_millis(jitter.unsigned_abs());
                sleep(d).await;
            }
            fut.await;
            drop(permit);
        });
        handles.push(handle);

    }
    for h in handles {
        let _ = h.await;
    }
}

/// Generates a random jitter in milliseconds based on the specified jitter value.
/// If `jitter_ms` is zero, it returns zero.
/// If `jitter_ms` is non-zero, it generates a random offset within the range of `-jitter_ms` to
/// `+jitter_ms`.
/// This function is used to add randomness to the execution time of jobs, helping to avoid
/// synchronized execution of multiple jobs.
fn rand_jitter_ms(rng: &mut ThreadRng, jitter_ms: u64) -> i64 {
    if jitter_ms == 0 {
        return 0;
    }
    let span = jitter_ms as i64;
    let offset: i64 = rng.gen_range(-span..=span);
    offset
}
