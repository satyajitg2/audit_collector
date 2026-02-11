use super::AuditSource;
use crate::model::FilterConfig;
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};

/// Source that reads from macOS 'log stream' command using dynamic filters.
pub struct MacLogSource {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    child_pid: Arc<Mutex<Option<u32>>>,
}

impl MacLogSource {
    pub fn new(config: FilterConfig) -> Result<Self> {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let q_clone = queue.clone();
        let child_pid = Arc::new(Mutex::new(None));
        let pid_clone = child_pid.clone();

        thread::spawn(move || {
            // Construct predicate string
            let mut predicates = Vec::new();
            if let Some(p) = config.process { 
                if !p.is_empty() { predicates.push(format!("process == \"{}\"", p)); }
            }
            if let Some(m) = config.message {
                if !m.is_empty() { predicates.push(format!("eventMessage contains \"{}\"", m)); }
            }
            if let Some(s) = config.subsystem {
                if !s.is_empty() { predicates.push(format!("subsystem == \"{}\"", s)); }
            }
            if let Some(pid_str) = config.pid {
                 if !pid_str.is_empty() { predicates.push(format!("processID == {}", pid_str)); }
            }
            if let Some(t) = config.thread_id {
                 if !t.is_empty() { predicates.push(format!("threadID == {}", t)); }
            }
            if let Some(c) = config.category {
                 if !c.is_empty() { predicates.push(format!("category == \"{}\"", c)); }
            }
            // Library/Image path filtering in predicates usually checks processImagePath
            if let Some(l) = config.library {
                 if !l.is_empty() { predicates.push(format!("processImagePath contains \"{}\"", l)); }
            }

            let predicate_arg = if predicates.is_empty() {
                "".to_string()
            } else {
                predicates.join(" AND ")
            };

            let mut cmd = Command::new("/usr/bin/log");
            cmd.arg("stream").arg("--style").arg("json"); // Use JSON for easier parsing
            
            if !predicate_arg.is_empty() {
                cmd.arg("--predicate").arg(predicate_arg);
            }

            println!("Starting log stream with predicate: {:?}", cmd);

            let mut child = cmd
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to spawn log stream");
            
            if let Ok(mut pid_lock) = pid_clone.lock() {
                *pid_lock = Some(child.id());
            }

            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        let trimmed = l.trim();
                        // log stream --style json outputs an array of objects [{}, {}]
                        // or one object per line depending on version/buffering.
                        // Usually it's a stream of JSON objects but seemingly in an array structure often.
                        // We will just push valid non-empty lines and handle parsing in collector.
                        if !trimmed.is_empty() && trimmed != "[" && trimmed != "]" && trimmed != "]," {
                             // clean up trailing comma if present (common in log stream json output)
                             let clean_line = trimmed.trim_end_matches(',');
                             q_clone.lock().unwrap().push_back(clean_line.as_bytes().to_vec());
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

impl AuditSource for MacLogSource {
    fn receive(&self) -> Result<Vec<u8>> {
        loop {
            let mut q = self.queue.lock().unwrap();
            if let Some(data) = q.pop_front() {
                return Ok(data);
            }
            drop(q);
            
            // Check if child is still running? For now just sleep.
            thread::sleep(Duration::from_millis(50));
        }
    }
    
    fn stop(&self) {
        let pid_opt = self.child_pid.lock().unwrap();
        if let Some(pid) = *pid_opt {
            // Kill the process
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    }
}
