use crate::model::AuditEvent;
use crate::source::AuditSource;
use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use std::sync::Arc;


/// The Collector orchestrates reading from the source, parsing, and sending to the pipeline.
pub struct Collector {
    source: Arc<dyn AuditSource>,
    sender: Sender<AuditEvent>,
}

impl Collector {
    /// Creates a new Collector with a source and a destination channel.
    pub fn new(source: Arc<dyn AuditSource>, sender: Sender<AuditEvent>) -> Self {
        Self { source, sender }
    }

    /// Runs the collector loop. This consumes the current thread.
    pub fn run(&self) -> Result<()> {
        loop {
            // 1. Receive Raw Data
            let raw_data = self.source.receive().context("Failed to receive audit data")?;
            
            if raw_data.is_empty() {
                continue;
            }

            // 2. Parse Data (Simulated for this exercise since raw_data structure varies)
            // In a real netlink implementation, we would parse the nlmsghdr first.
            // Here we assume raw_data is the payload string for simplicity of the Mock.
            if let Ok(event) = self.parse_event(&raw_data) {
                // 3. Send to Pipeline
                if let Err(_) = self.sender.send(event) {
                    println!("Receiver dropped, stopping collector.");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Parses raw bytes into an AuditEvent.
    /// 
    /// Assumptions for this simplified implementation:
    /// - Input bytes are ASCII string representation of an audit log line.
    /// - Format: `type=1300 ... key=value ...`
    fn parse_event(&self, raw: &[u8]) -> Result<AuditEvent> {
        let s = String::from_utf8_lossy(raw);
        
        // Defaults
        let mut type_id = 0;
        let mut serial = 0;
        let mut fields = std::collections::HashMap::new();

        // Check if it's JSON (macOS log stream --style json)
        if s.trim().starts_with('{') {
             // Try parsing as MacLogEntry
             if let Ok(entry) = serde_json::from_str::<crate::model::MacLogEntry>(&s) {
                 type_id = 1; // Generic Type
                 
                 if let Some(msg) = entry.event_message {
                     fields.insert("message".to_string(), msg);
                 }
                 if let Some(proc) = entry.process_image_path.clone() {
                     fields.insert("process".to_string(), proc);
                 }
                 if let Some(pid) = entry.process_id {
                     fields.insert("pid".to_string(), pid.to_string());
                 }
                 if let Some(tid) = entry.thread_id {
                     fields.insert("thread_id".to_string(), tid.to_string());
                 }
                 if let Some(sub) = entry.subsystem {
                     fields.insert("subsystem".to_string(), sub);
                 }
                 if let Some(cat) = entry.category {
                     fields.insert("category".to_string(), cat);
                 }
                 if let Some(lib) = entry.process_image_path.as_ref() { 
                      // Sometimes image path is the library if it's loaded dylib vs executable? 
                      // Actually processImagePath is usually the main executable.
                      fields.insert("library".to_string(), lib.clone());
                 }
                 
                 return Ok(AuditEvent {
                     timestamp: chrono::Utc::now(), // Ideally parse entry.timestamp
                     record_type: type_id,
                     sequence: serial,
                     fields,
                 });
             }
        }

        // Legacy/Linux Audit Format: type=1300 ... key=value ...
        if s.contains("type=") && s.contains("msg=audit") {
            for part in s.split_whitespace() {
                if let Some((k, v)) = part.split_once('=') {
                     fields.insert(k.to_string(), v.to_string());
                     if k == "type" {
                         let digits: String = v.chars().filter(|c| c.is_digit(10)).collect();
                         type_id = digits.parse().unwrap_or(0);
                     }
                     if k == "msg" {
                        // serial parsing logic
                        if let Some(start) = v.find(':') {
                            if let Some(end) = v.find(')') {
                                if start < end {
                                    let seq_str = &v[start+1..end];
                                    serial = seq_str.parse().unwrap_or(0);
                                }
                            }
                        }
                     }
                }
            }
        } else if !s.trim().starts_with('{') {
            // Fallback for non-JSON generic logs
            type_id = 1; 
            fields.insert("message".to_string(), s.to_string());
        }

        Ok(AuditEvent {
            timestamp: chrono::Utc::now(),
            record_type: type_id,
            sequence: serial,
            fields,
        })
    }
}
