use std::{future::Future, sync::Arc, time::Duration};

use rand::{rngs::ThreadRng, Rng};
use tokio::{sync::Semaphore, time::sleep};


#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub base_delay_ms: u64,
    pub jitter_ms: u64,
    pub max_inflight: usize,
}

impl SchedulerConfig {
    pub fn new(base_delay_ms: u64, jitter_ms: u64, max_inflight: usize) -> Self {
        Self {
            base_delay_ms,
            jitter_ms,
            max_inflight: max_inflight.max(1),
        }
    }
}

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

fn rand_jitter_ms(rng: &mut ThreadRng, jitter_ms: u64) -> i64 {
    if jitter_ms == 0 {
        return 0;
    }
    let span = jitter_ms as i64;
    let offset: i64 = rng.gen_range(-span..=span);
    offset
}
