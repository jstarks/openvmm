// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use parking_lot::RwLock;
use parking_lot::RwLockReadGuard;
use std::ops::Range;
use std::sync::Arc;
use thiserror::Error;

/// Observes completed external write attempts, including attempts that fail
/// after modifying memory or unwind. The range is conservative, not an exact
/// written prefix.
///
/// Callbacks are trusted, infallible, local operations. They must not reenter
/// writes or registration, perform remote transport, or wait on work that needs
/// the registration gate. Callbacks must not panic, including when invoked
/// while a backing operation is unwinding.
pub trait WriteObserver: Send + Sync {
    /// Invalidates observations of the supplied range before the writer returns.
    fn notify_write(&self, range: Range<u64>);
}

struct Inner {
    gate: RwLock<()>,
    observer: Arc<dyn WriteObserver>,
}

/// A shared write/registration gate and an address-space translation.
///
/// Concurrent writes hold a shared gate through the complete attempt and its
/// callback. Registration and capture use [`Self::synchronize`]. The gate can
/// span backing fault handling: callbacks, registration closures, and backing
/// fault handlers must not form wait cycles. Initial integrations should use
/// eager, local mappings rather than remote or blocking fault resolution.
#[derive(Clone)]
pub struct WriteTracker {
    inner: Arc<Inner>,
    offset: u64,
}

impl std::fmt::Debug for WriteTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteTracker")
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// The translated write range cannot be represented.
#[derive(Debug, Error)]
#[error("write observer address overflow")]
pub struct WriteTrackerError;

impl WriteTracker {
    /// Creates a tracker for an observer's address space.
    pub fn new(observer: Arc<dyn WriteObserver>) -> Self {
        Self {
            inner: Arc::new(Inner {
                gate: RwLock::new(()),
                observer,
            }),
            offset: 0,
        }
    }

    /// Runs registration/capture exclusively against writes and callbacks.
    ///
    /// The closure must not reenter a write or this gate.
    pub fn synchronize<T>(&self, f: impl FnOnce() -> T) -> T {
        let _guard = self.inner.gate.write();
        f()
    }

    /// Creates a descriptor whose address zero is `offset` in this descriptor.
    pub fn with_offset(&self, offset: u64) -> Result<Self, WriteTrackerError> {
        Ok(Self {
            inner: self.inner.clone(),
            offset: self.offset.checked_add(offset).ok_or(WriteTrackerError)?,
        })
    }

    /// Notifies after a mapping change, under the shared registration gate.
    ///
    /// Empty ranges do not notify. Overflow is rejected without a callback.
    /// This does not guard a preceding write; mediated writes instead hold the
    /// gate over both the memory operation and the callback.
    pub fn notify_write(&self, address: u64, len: usize) -> Result<(), WriteTrackerError> {
        if len != 0 {
            drop(self.begin_write(address, len)?);
        }
        Ok(())
    }

    pub(crate) fn begin_write(
        &self,
        address: u64,
        len: usize,
    ) -> Result<WriteAttempt<'_>, WriteTrackerError> {
        let start = self.offset.checked_add(address).ok_or(WriteTrackerError)?;
        let end = start.checked_add(len as u64).ok_or(WriteTrackerError)?;
        Ok(WriteAttempt {
            tracker: self,
            range: start..end,
            _guard: self.inner.gate.read(),
        })
    }
}

pub(crate) struct WriteAttempt<'a> {
    tracker: &'a WriteTracker,
    range: Range<u64>,
    _guard: RwLockReadGuard<'a, ()>,
}

impl Drop for WriteAttempt<'_> {
    fn drop(&mut self) {
        // Keep the shared gate until notification finishes, even on unwind.
        self.tracker.inner.observer.notify_write(self.range.clone());
    }
}

#[cfg(test)]
mod tests;
