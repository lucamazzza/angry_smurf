use std::{fs::File, io::{BufWriter, Write}, path::PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;

#[derive(Serialize, Debug, Clone)]
pub struct Event {
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub iface: String,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Clone)]
pub struct Logger {
    tx: mpsc::UnboundedSender<Event>,
}

impl Logger {
    pub fn new(out: Option<PathBuf>) -> Result<Self> {
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        match out {
            Some(path) => {
                let file = File::create(path)?;
                let mut writer = BufWriter::new(file);
                tokio::spawn(async move {
                   while let Some(ev) = rx.recv().await {
                        if let Ok(line) = serde_json::to_vec(&ev) {
                            let _ = writer.write_all(&line);
                            let _ = writer.write_all(b"\n");
                            let _ = writer.flush();
                        }
                   } 
                });
            }
            None => {
                tokio::task::spawn_blocking(move || {
                    let stdout = std::io::stdout();
                    let mut handle = stdout.lock();
                    while let Some(ev) = rx.blocking_recv() {
                        if let Ok(line) = serde_json::to_vec(&ev) {
                            let _ = handle.write_all(&line);
                            let _ = handle.write_all(b"\n");
                            let _ = handle.flush();
                        }
                    }
                });
            }
        }
        Ok(Self { tx })
    }

    pub fn log(&self, mut ev: Event) {
        if ev.ts.timestamp_millis() == 0 {
            ev.ts = Utc::now();
        }
        let _ = self.tx.send(ev);
    }
}

pub fn ev(
    kind: &str,
    iface: &str,
    src: Option<&str>,
    dst: Option<&str>,
    details: serde_json::Value,
) -> Event {
    Event {
        ts: Utc::now(),
        kind: kind.to_string(),
        iface: iface.to_string(),
        src: src.map(|s| s.to_string()),
        dst: dst.map(|s| s.to_string()),
        details,
    }
}
