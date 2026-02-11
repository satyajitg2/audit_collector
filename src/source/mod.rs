use anyhow::Result;


pub trait AuditSource: Send + Sync {
    /// Blocks until a new packet of data is available.
    fn receive(&self) -> Result<Vec<u8>>;
    /// Optional: Signal to stop the source
    fn stop(&self) {}
}

pub mod mock;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

// Re-export common types if necessary
pub use mock::MockAuditSource;
#[cfg(target_os = "macos")]
pub use macos::MacLogSource;
#[cfg(target_os = "linux")]
pub use linux::LinuxAuditSource;
#[cfg(target_os = "windows")]
pub use windows::WindowsEventSource;
