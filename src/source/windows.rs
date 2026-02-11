use super::AuditSource;
use anyhow::{Result, anyhow};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::ptr::null_mut;
use std::ffi::c_void;

use windows::Win32::Foundation::{HANDLE, ERROR_NO_MORE_ITEMS, WAIT_OBJECT_0, CloseHandle};
use windows::Win32::System::EventLog::{
    EvtSubscribe, EvtRender, EvtRenderEventXml, EvtClose, 
    EVT_SUBSCRIBE_FLAGS, EvtSubscribeToFutureEvents, EvtNext
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows::core::{PCWSTR, PWSTR};

/// Connects to Windows Event Log
pub struct WindowsEventSource {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    stop_signal: Arc<Mutex<bool>>,
}

// Safety: Windows handles need to be handled carefully across threads, 
// strictly simplified here for the example. Ensure Send/Sync wrappers in real prod code.
unsafe impl Send for WindowsEventSource {}
unsafe impl Sync for WindowsEventSource {}

impl WindowsEventSource {
    pub fn new() -> Result<Self> {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let q_clone = queue.clone();
        let stop_signal = Arc::new(Mutex::new(false));
        let stop_clone = stop_signal.clone();

        thread::spawn(move || {
            unsafe {
                // Subscribe to the Security log
                // In a real app, query might be configurable
                let query = windows::core::w!("Security"); 
                
                let signal_event = CreateEventW(None, false, false, None).unwrap();
                
                // Subscribe
                let subscription = EvtSubscribe(
                    None,
                    signal_event,
                    query,
                    None,
                    None,
                    c_void::null_mut(),
                    None,
                    EvtSubscribeToFutureEvents
                );

                if subscription.is_invalid() {
                    eprintln!("Failed to subscribe to Windows Event Log");
                    return;
                }
                
                println!("Subscribed to Windows Security Audit Log");

                loop {
                    // Check stop signal
                    if *stop_clone.lock().unwrap() {
                        break;
                    }

                    // Wait for event (timeout 1s to allow checking stop signal)
                    let wait_result = WaitForSingleObject(signal_event, 1000);
                    
                    if wait_result == WAIT_OBJECT_0 {
                         // We have events.
                         // We need to fetch them using EvtNext if we were using a different subscription model,
                         // But for Signal based subscription, we can just call EvtNext on the subscription handle?
                         // Actually, standard pattern with Signal is to use EvtNext on the subscription handle.
                         
                         let mut events: [isize; 10] = [0; 10]; // Array of handles (isize/HANDLE)
                         let mut returned: u32 = 0;
                         
                         // Note: EvtNext takes EVT_HANDLE which is isize in windows-rs crate often, or parsed wrapper.
                         // Let's check windows-rs signatures. 
                         // Assuming strictly raw handles here for simplicity or using the crate types.
                         // subscription is of type EVT_HANDLE.
                         
                         // Note: windows-rs 0.52 EVT_HANDLE is a struct.
                         
                         let mut event_handles: [windows::Win32::System::EventLog::EVT_HANDLE; 5] = Default::default();
                         
                         if EvtNext(subscription, &mut event_handles, 1000, 0, &mut returned).as_bool() {
                             for i in 0..returned {
                                 let h_evt = event_handles[i as usize];
                                 if !h_evt.is_invalid() {
                                     if let Ok(xml) = render_event_xml(h_evt) {
                                         // Convert simple XML to a "fake" JSON or just pass XML bytes?
                                         // The collector expects JSON or key=value.
                                         // Let's wrap it in a JSON structure so the existing parser catches it.
                                         let json = format!("{{ \"message\": \"Windows Event\", \"details\": {:?} }}", xml);
                                         q_clone.lock().unwrap().push_back(json.as_bytes().to_vec());
                                     }
                                     EvtClose(h_evt);
                                 }
                             }
                         }
                    }
                }
                
                EvtClose(subscription);
                CloseHandle(signal_event);
            }
        });

        Ok(Self { queue, stop_signal })
    }
}

unsafe fn render_event_xml(event: windows::Win32::System::EventLog::EVT_HANDLE) -> Result<String> {
    // Call EvtRender with EvtRenderEventXml
    let mut buffer_used: u32 = 0;
    let mut property_count: u32 = 0;
    
    // First call to get size (will fail with ERROR_INSUFFICIENT_BUFFER usually)
    let _ = EvtRender(None, event, EvtRenderEventXml, 0, null_mut(), &mut buffer_used, &mut property_count);
    
    if buffer_used == 0 {
        return Ok("".to_string());
    }

    let mut buffer: Vec<u16> = vec![0; (buffer_used / 2) as usize];
    
    if EvtRender(None, event, EvtRenderEventXml, buffer_used, buffer.as_mut_ptr() as *mut c_void, &mut buffer_used, &mut property_count).as_bool() {
        return Ok(String::from_utf16_lossy(&buffer));
    }
    
    Err(anyhow!("Failed to render XML"))
}


impl AuditSource for WindowsEventSource {
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
        *self.stop_signal.lock().unwrap() = true;
    }
}
