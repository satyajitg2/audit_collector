use audit_collector::collector::Collector;
use audit_collector::source::MockAuditSource;
use audit_collector::model::AuditEvent;
use crossbeam_channel::unbounded;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_collector_pipeline() {
    // 1. Setup Mock Source with 2 sample audit messages
    let msg1 = b"type=1300 msg=audit(1674390000.123:100): arch=c000003e syscall=2 success=yes exit=0 a0=... items=1 ppid=1 pid=9999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=1 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"audit_test\"".to_vec();
    
    let msg2 = b"type=1101 msg=audit(1674390005.456:101): pid=123 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct=\"root\" exe=\"/usr/sbin/cron\" hostname=? addr=? terminal=cron res=success'".to_vec();

    let source = Arc::new(MockAuditSource::new(vec![msg1, msg2]));

    // 2. Setup Channel
    let (tx, rx) = unbounded();

    // 3. Start Collector in a separate thread
    let collector = Collector::new(source.clone(), tx);
    thread::spawn(move || {
        // Run until source is empty (MockSource in this impl loops, but we can't easily break the loop in the current impl without a signal, 
        // so we'll just let it run and reading the expected count.)
        // Actually, let's fix the MockSource to return empty/error after depletion or just wait.
        // For this test, we just assume the collector runs.
        let _ = collector.run();
    });

    // 4. Assertions
    // Expect Event 1
    let event1 = rx.recv_timeout(Duration::from_secs(2)).expect("Failed to receive event 1");
    assert_eq!(event1.record_type, 1300);
    assert_eq!(event1.sequence, 100);
    assert_eq!(event1.fields.get("comm"), Some(&"\"cat\"".to_string()));
    assert_eq!(event1.fields.get("uid"), Some(&"1000".to_string()));

    // Expect Event 2
    let event2 = rx.recv_timeout(Duration::from_secs(2)).expect("Failed to receive event 2");
    assert_eq!(event2.record_type, 1101);
    assert_eq!(event2.sequence, 101);
    assert_eq!(event2.fields.get("pid"), Some(&"123".to_string()));

    println!("Test passed!");
}
