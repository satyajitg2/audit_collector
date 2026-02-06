use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Configuration for filtering events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FilterConfig {
    pub process: Option<String>,
    pub message: Option<String>,
    pub subsystem: Option<String>,
    pub pid: Option<String>,
    pub thread_id: Option<String>,
    pub category: Option<String>,
    pub library: Option<String>,
}

/// Represents a single audit event captured from the kernel.
/// 
/// This structure is the "canonical" representation used throughout the 
/// processing pipeline (Filter -> Enrichment -> Output).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Timestamp when the event occurred (from kernel or reception time).
    pub timestamp: DateTime<Utc>,
    
    /// The audit record type (e.g., 1300 for AUDIT_SYSCALL or 1 for GENERIC).
    pub record_type: u16,
    
    /// The unique sequence number (serial) of the audit event.
    pub sequence: u32,

    /// Key-value pairs parsed from the raw audit message.
    pub fields: HashMap<String, String>,
}

impl AuditEvent {
    /// Creates a new empty AuditEvent.
    pub fn new(record_type: u16, sequence: u32) -> Self {
        Self {
            timestamp: Utc::now(),
            record_type,
            sequence,
            fields: HashMap::new(),
        }
    }
}

/// Helper struct to parse macOS JSON log output
#[derive(Debug, Deserialize)]
pub struct MacLogEntry {
    pub timestamp: Option<String>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub processImagePath: Option<String>,
    pub processID: Option<u64>,
    pub threadID: Option<u64>,
    pub eventMessage: Option<String>,
    pub messageType: Option<String>,
}
