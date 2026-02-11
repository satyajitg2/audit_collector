use super::AuditSource;
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

/// A Mock source that replays a predefined sequence of byte vectors.
pub struct MockAuditSource {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl MockAuditSource {
    pub fn new(data: Vec<Vec<u8>>) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::from(data))),
        }
    }
    pub fn push(&self, packet: Vec<u8>) {
        self.queue.lock().unwrap().push_back(packet);
    }
}

impl AuditSource for MockAuditSource {
    fn receive(&self) -> Result<Vec<u8>> {
        loop {
            let mut q = self.queue.lock().unwrap();
            if let Some(data) = q.pop_front() {
                return Ok(data);
            }
            drop(q);
            thread::sleep(Duration::from_millis(100));
        }
    }
}
