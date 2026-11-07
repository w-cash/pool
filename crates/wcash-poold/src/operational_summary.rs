//! Fixed-size, process-only summaries emitted by the existing portal refresh loop.

use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::{mpsc, Arc, OnceLock},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};
use tokio::time::Instant;
use wcash_pool_edge::OperationalCounters;

use crate::edge::EdgeCounters;

const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);
const SUMMARY_QUEUE_CAPACITY: usize = 2;
const MAX_SUMMARY_BYTES: usize = 8_192;

static PROCESS_SINK: OnceLock<SummarySink> = OnceLock::new();

type WriterTask = Box<dyn FnOnce() + Send>;

/// Only this detached process-lifetime worker may wait for the log destination.
/// Producers never drain or join it, including during service shutdown.
#[derive(Clone)]
struct SummarySink {
    sender: Option<mpsc::SyncSender<Vec<u8>>>,
}

impl SummarySink {
    fn start<W, S>(mut writer: W, spawn: S) -> (Self, Option<JoinHandle<()>>)
    where
        W: Write + Send + 'static,
        S: FnOnce(WriterTask) -> io::Result<JoinHandle<()>>,
    {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(SUMMARY_QUEUE_CAPACITY);
        let task = Box::new(move || {
            while let Ok(record) = receiver.recv() {
                // Logging failure must neither panic nor recursively log itself.
                // A partially written record is best effort, not a durable event.
                let _ = writer.write_all(&record);
            }
        });
        match spawn(task) {
            Ok(handle) => (
                Self {
                    sender: Some(sender),
                },
                Some(handle),
            ),
            Err(_) => (Self { sender: None }, None),
        }
    }

    fn process() -> Self {
        PROCESS_SINK
            .get_or_init(|| {
                let (sink, handle) = Self::start(io::stderr(), |task| {
                    thread::Builder::new()
                        .name("frontend-summary-log".into())
                        .spawn(task)
                });
                // Dropping a JoinHandle detaches it. A blocked log destination
                // must not become a service drain or process shutdown barrier.
                drop(handle);
                sink
            })
            .clone()
    }

    fn enqueue(&self, value: &Value) {
        let Some(sender) = &self.sender else {
            return;
        };
        let mut record = BoundedRecord(Vec::with_capacity(MAX_SUMMARY_BYTES));
        if serde_json::to_writer(&mut record, value).is_err() || record.write_all(b"\n").is_err() {
            return;
        }
        // A full/disconnected queue drops this observation; it never delays a
        // serving task or creates an unbounded pending log allocation.
        let _ = sender.try_send(record.0);
    }
}

/// Serialization is bounded too, so future schema growth cannot queue a large record.
struct BoundedRecord(Vec<u8>);

impl Write for BoundedRecord {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_SUMMARY_BYTES - self.0.len() {
            return Err(io::Error::other("summary size limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A rate ceiling independent of refresh-loop frequency; missed intervals never burst.
pub(crate) struct OperationalSummary {
    diagnostics: Arc<OperationalCounters>,
    connections: Arc<EdgeCounters>,
    next: Instant,
    sink: SummarySink,
}

impl OperationalSummary {
    pub(crate) fn new(
        diagnostics: Arc<OperationalCounters>,
        connections: Arc<EdgeCounters>,
    ) -> Self {
        Self::with_sink(diagnostics, connections, SummarySink::process())
    }

    fn with_sink(
        diagnostics: Arc<OperationalCounters>,
        connections: Arc<EdgeCounters>,
        sink: SummarySink,
    ) -> Self {
        Self {
            diagnostics,
            connections,
            next: Instant::now(),
            sink,
        }
    }

    pub(crate) fn take_if_due(&mut self, now: Instant) -> Option<Value> {
        if now < self.next {
            return None;
        }
        self.next = now + SUMMARY_INTERVAL;
        Some(summary(&self.diagnostics, &self.connections))
    }

    pub(crate) fn emit_if_due(&mut self) {
        if let Some(value) = self.take_if_due(Instant::now()) {
            self.sink.enqueue(&value);
        }
    }
}

pub(crate) fn emit_final(diagnostics: &OperationalCounters, connections: &EdgeCounters) {
    // A failed/absent startup logger must not be retried or created at shutdown.
    if let Some(sink) = PROCESS_SINK.get() {
        emit_final_to(sink, diagnostics, connections);
    }
}

fn emit_final_to(
    sink: &SummarySink,
    diagnostics: &OperationalCounters,
    connections: &EdgeCounters,
) {
    let mut value = summary(diagnostics, connections);
    value["final"] = Value::Bool(true);
    sink.enqueue(&value);
}

fn summary(diagnostics: &OperationalCounters, connections: &EdgeCounters) -> Value {
    let counters: BTreeMap<_, _> = diagnostics.snapshot().into_iter().collect();
    let connections: BTreeMap<_, _> = connections.snapshot().into_iter().collect();
    json!({
        "event": "frontend_operational_summary",
        "schema": 1,
        "process_instance_id": diagnostics.instance_id(),
        "process_started_at_unix": diagnostics.started_at_unix(),
        "sampled_at_unix": SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs()),
        "uptime_seconds": diagnostics.uptime_seconds(),
        "scope": "process_lifetime_best_effort_not_accounting",
        "final": false,
        "counters": counters,
        "connections": connections,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use wcash_pool_edge::Diagnostic;

    struct CaptureWriter(mpsc::Sender<Vec<u8>>);

    impl Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.0.send(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BrokenWriter(mpsc::Sender<()>);

    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            let _ = self.0.send(());
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BlockedWriter {
        entered: mpsc::Sender<()>,
        release: Option<mpsc::Receiver<()>>,
        records: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(release) = self.release.take() {
                let _ = self.entered.send(());
                let _ = release.recv();
            }
            self.records.lock().unwrap().push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Always release a blocked test writer before joining it, including on panic.
    /// Reporter clones are declared after this owner and drop before it unwinds.
    struct OwnedWriter {
        sink: SummarySink,
        handle: Option<JoinHandle<()>>,
        release: Option<mpsc::Sender<()>>,
    }

    impl OwnedWriter {
        fn new(writer: impl Write + Send + 'static) -> Self {
            let (sink, handle) =
                SummarySink::start(writer, |task| thread::Builder::new().spawn(task));
            Self {
                sink,
                handle,
                release: None,
            }
        }

        fn unblock(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
        }

        fn finish(&mut self) {
            self.unblock();
            self.sink.sender.take();
            if let Some(handle) = self.handle.take() {
                assert!(handle.join().is_ok());
            }
        }
    }

    impl Drop for OwnedWriter {
        fn drop(&mut self) {
            self.unblock();
            self.sink.sender.take();
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn test_reporter(sink: SummarySink) -> OperationalSummary {
        OperationalSummary::with_sink(
            Arc::new(OperationalCounters::default()),
            Arc::new(EdgeCounters::default()),
            sink,
        )
    }

    #[test]
    fn operational_summary_healthy_writer_preserves_periodic_and_final_json() {
        let (sent, received) = mpsc::channel();
        let mut writer = OwnedWriter::new(CaptureWriter(sent));
        let mut reporter = test_reporter(writer.sink.clone());
        reporter.diagnostics.record(Diagnostic::SubmitObserved);
        reporter.emit_if_due();
        reporter.emit_if_due(); // The normal rate ceiling still suppresses this call.
        emit_final_to(&writer.sink, &reporter.diagnostics, &reporter.connections);
        let expected = summary(&reporter.diagnostics, &reporter.connections);
        drop(reporter);
        writer.finish();

        let records: Vec<_> = received.try_iter().collect();
        assert_eq!(records.len(), 2);
        for (index, record) in records.iter().enumerate() {
            assert!(record.len() <= MAX_SUMMARY_BYTES);
            assert_eq!(record.last(), Some(&b'\n'));
            let value: Value = serde_json::from_slice(record).unwrap();
            let mut expected = expected.clone();
            expected["final"] = Value::Bool(index == 1);
            // These are sampled at emission, not sink-write time.
            expected["sampled_at_unix"] = value["sampled_at_unix"].clone();
            expected["uptime_seconds"] = value["uptime_seconds"].clone();
            assert_eq!(value, expected);
        }
    }

    #[tokio::test]
    async fn operational_summary_broken_pipe_does_not_panic_emitting_task() {
        let (attempted, attempts) = mpsc::channel();
        let mut writer = OwnedWriter::new(BrokenWriter(attempted));
        let sink = writer.sink.clone();
        let task = tokio::spawn(async move {
            let mut reporter = test_reporter(sink);
            reporter.emit_if_due();
            emit_final_to(&reporter.sink, &reporter.diagnostics, &reporter.connections);
            // The existing service reacts to task exit/panic, so check the actual
            // emitter remains usable rather than only testing a standalone Write.
            reporter.diagnostics.record(Diagnostic::SubmitObserved);
            reporter.diagnostics.snapshot()
        });
        let observations = task.await.unwrap();
        assert!(observations.iter().any(|(label, count)| {
            *label == Diagnostic::SubmitObserved.as_str() && *count == 1
        }));
        writer.finish();
        assert_eq!(attempts.try_iter().count(), 2);
    }

    #[test]
    fn operational_summary_blocked_writer_bounds_queue_and_never_waits_for_final() {
        let (entered, entry) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let records = Arc::new(Mutex::new(Vec::new()));
        let mut writer = OwnedWriter::new(BlockedWriter {
            entered,
            release: Some(released),
            records: Arc::clone(&records),
        });
        writer.release = Some(release);
        let mut first = test_reporter(writer.sink.clone());
        first.emit_if_due();
        let entered = entry.recv_timeout(Duration::from_secs(1));
        if entered.is_err() {
            drop(first);
            writer.finish();
            panic!("test writer did not receive the startup record");
        }
        let sink = writer.sink.clone();
        let (finished, completion) = mpsc::channel();
        let producer = thread::spawn(move || {
            let mut reporter = test_reporter(sink);
            for _ in 0..4 {
                reporter.next = Instant::now();
                reporter.emit_if_due();
            }
            emit_final_to(&reporter.sink, &reporter.diagnostics, &reporter.connections);
            let _ = finished.send(());
        });
        let completed_while_blocked = completion.recv_timeout(Duration::from_secs(1));
        // Release before any assertion/join, even if a regression delayed the producer.
        writer.unblock();
        let producer_result = producer.join();
        drop(first);
        writer.finish();
        assert!(completed_while_blocked.is_ok());
        assert!(producer_result.is_ok());
        let records = records.lock().unwrap();
        assert_eq!(records.len(), 1 + SUMMARY_QUEUE_CAPACITY);
        assert!(records
            .iter()
            .all(|record| record.len() <= MAX_SUMMARY_BYTES));
    }

    #[test]
    fn operational_summary_spawn_failure_and_disconnection_fail_open() {
        let (sink, handle) = SummarySink::start(io::sink(), |_| {
            Err(io::Error::other("injected spawn failure"))
        });
        assert!(handle.is_none());
        assert!(sink.sender.is_none());
        let mut reporter = test_reporter(sink);
        reporter.emit_if_due();
        emit_final_to(&reporter.sink, &reporter.diagnostics, &reporter.connections);

        let (sender, receiver) = mpsc::sync_channel(SUMMARY_QUEUE_CAPACITY);
        drop(receiver);
        let sink = SummarySink {
            sender: Some(sender),
        };
        let mut reporter = test_reporter(sink);
        reporter.emit_if_due();
        emit_final_to(&reporter.sink, &reporter.diagnostics, &reporter.connections);
    }

    #[test]
    fn operational_summary_rejects_oversize_before_queueing() {
        let (sender, receiver) = mpsc::sync_channel(SUMMARY_QUEUE_CAPACITY);
        let sink = SummarySink {
            sender: Some(sender),
        };
        sink.enqueue(&json!({"oversize": "x".repeat(MAX_SUMMARY_BYTES)}));
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn operational_summary_is_bounded_and_never_catches_up_in_bursts() {
        let counters = Arc::new(OperationalCounters::default());
        for &d in Diagnostic::ALL {
            counters.record(d);
        }
        let mut reporter = OperationalSummary::with_sink(
            counters,
            Arc::new(EdgeCounters::default()),
            SummarySink { sender: None },
        );
        let now = reporter.next;
        let first = reporter.take_if_due(now);
        assert!(first.is_some());
        assert!(reporter.take_if_due(now).is_none());
        assert!(reporter
            .take_if_due(now + Duration::from_secs(59))
            .is_none());
        assert!(reporter
            .take_if_due(now + Duration::from_secs(600))
            .is_some());
        assert!(reporter
            .take_if_due(now + Duration::from_secs(600))
            .is_none());
        let encoded = first
            .map(|mut value| {
                if let Some(counters) = value["counters"].as_object_mut() {
                    for counter in counters.values_mut() {
                        *counter = Value::from(u64::MAX);
                    }
                }
                value.to_string()
            })
            .unwrap_or_default();
        assert!(encoded.len() < 8_192);
        assert!(!encoded.contains("account_id"));
        assert!(!encoded.contains("worker_id"));
        assert!(!encoded.contains("solution"));
        assert!(!encoded.contains("password"));
    }
}
