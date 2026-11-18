//! Progress reporting for a scan.

/// A step in running the analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressEvent {
    Started { id: &'static str },
    Finished { id: &'static str, signals: usize },
    Failed { id: &'static str },
}

/// Receives progress events.
pub trait ProgressSink: Send + Sync {
    fn event(&self, e: ProgressEvent);
}

/// A sink that ignores every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopProgress;

impl ProgressSink for NoopProgress {
    fn event(&self, _e: ProgressEvent) {}
}
