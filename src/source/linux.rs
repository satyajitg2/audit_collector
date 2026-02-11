use super::AuditSource;
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};

/// Source that reads from Linux audit log file.
/// For this implementation, we simply tail /var/log/audit/audit.log
/// This requires the application to have read permissions on that file.
pub struct LinuxAuditSource {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    child_pid: Arc<Mutex<Option<u32>>>,
}

impl LinuxAuditSource {
    pub fn new() -> Result<Self> {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let q_clone = queue.clone();
        let child_pid = Arc::new(Mutex::new(None));
        let pid_clone = child_pid.clone();

        thread::spawn(move || {
            let mut cmd = Command::new("tail");
            cmd.arg("-f").arg("/var/log/audit/audit.log");

            println!("Starting audit log stream: {:?}", cmd);

            let mut child = cmd
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to spawn tail process");
            
            if let Ok(mut pid_lock) = pid_clone.lock() {
                *pid_lock = Some(child.id());
            }

            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        let trimmed = l.trim();
                        if !trimmed.is_empty() {
                             q_clone.lock().unwrap().push_back(trimmed.as_bytes().to_vec());
                        }
                    }
                }
            }
            // Child exited
            let mut pid_lock = pid_clone.lock().unwrap();
            *pid_lock = None;
        });

        Ok(Self { queue, child_pid })
    }
}

impl AuditSource for LinuxAuditSource {
    fn receive(&self) -> Result<Vec<u8>> {
        loop {
            let mut q = self.queue.lock().unwrap();
            if let Some(data) = q.pop_front() {
                return Ok(data);
            }
            drop(q);
            thread::sleep(Duration::from_millis(50));
        }
    }
    
    fn stop(&self) {
        let pid_opt = self.child_pid.lock().unwrap();
        if let Some(pid) = *pid_opt {
             let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    }
}
