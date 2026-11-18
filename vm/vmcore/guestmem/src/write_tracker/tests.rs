// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::AccessType;
use crate::AlignedHeapMemory;
use crate::GuestMemory;
use crate::GuestMemoryAccess;
use crate::GuestMemoryBackingError;
use crate::PageFaultAction;
use guestmem_core::ranges::PagedRange;
use parking_lot::Mutex;
use sparse_mmap::SparseMapping;
use std::ptr::NonNull;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use test_with_tracing::test;

#[derive(Default)]
struct Recorder(Mutex<Vec<Range<u64>>>);

impl WriteObserver for Recorder {
    fn notify_write(&self, range: Range<u64>) {
        self.0.lock().push(range);
    }
}

struct Observed<T> {
    backing: T,
    tracker: WriteTracker,
}

// SAFETY: all pointer and fallback contracts are provided by the inner backing.
unsafe impl<T: GuestMemoryAccess> GuestMemoryAccess for Observed<T> {
    fn mapping(&self) -> Option<NonNull<u8>> {
        self.backing.mapping()
    }

    fn max_address(&self) -> u64 {
        self.backing.max_address()
    }

    fn write_tracker(&self) -> Option<WriteTracker> {
        Some(self.tracker.clone())
    }

    fn page_fault(&self, address: u64, len: usize, write: bool, bitmap: bool) -> PageFaultAction {
        self.backing.page_fault(address, len, write, bitmap)
    }

    unsafe fn write_fallback(
        &self,
        address: u64,
        src: *const u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        // SAFETY: the caller supplies the source buffer contract.
        unsafe { self.backing.write_fallback(address, src, len) }
    }

    fn fill_fallback(
        &self,
        address: u64,
        value: u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        self.backing.fill_fallback(address, value, len)
    }

    fn supports_kernel_lock(&self) -> bool {
        true
    }

    fn supports_user_lock(&self) -> bool {
        true
    }

    fn lock_kernel_gpns(&self, _: &[u64]) -> Result<bool, GuestMemoryBackingError> {
        panic!("observed views must not call backing lock hooks")
    }

    fn lock_user_gpns(&self, _: &[u64]) -> Result<bool, GuestMemoryBackingError> {
        panic!("observed views must not call backing lock hooks")
    }

    fn subrange(
        &self,
        _: u64,
        _: u64,
        _: bool,
    ) -> Result<Option<GuestMemory>, GuestMemoryBackingError> {
        panic!("observed views must not call custom subrange hooks")
    }

    fn base_iova(&self) -> Option<u64> {
        Some(0)
    }

    fn sharing(&self) -> Option<crate::GuestMemorySharing> {
        panic!("observed views must not expose backing sharing handles")
    }
}

#[test]
fn mapped_writes_and_nonwriting_accesses() {
    let recorder = Arc::new(Recorder::default());
    let gm = GuestMemory::new(
        "observed",
        Observed {
            backing: AlignedHeapMemory::new(4096),
            tracker: WriteTracker::new(recorder.clone()),
        },
    );
    gm.write_at(1, &[1, 2, 3]).unwrap();
    gm.fill_at(5, 9, 3).unwrap();
    gm.write_plain(8, &42u64).unwrap();
    gm.write_from_atomic(20, &[AtomicU8::new(7)]).unwrap();
    assert!(gm.compare_exchange(8, 41u64, 3).unwrap().is_err());
    assert!(gm.compare_exchange(8, 42u64, 3).unwrap().is_ok());
    gm.probe_gpa_writable(30).unwrap();
    assert_eq!(
        *recorder.0.lock(),
        [1..4, 5..8, 8..16, 20..21, 8..16, 8..16, 30..31]
    );
    recorder.0.lock().clear();
    gm.read_at(1, &mut [0; 3]).unwrap();
    assert_eq!(gm.read_plain::<u64>(8).unwrap(), 3);
    gm.probe_gpa_readable(0).unwrap();
    gm.write_at(u64::MAX, &[]).unwrap();
    gm.fill_at(u64::MAX, 0, 0).unwrap();
    gm.write_plain(0, &[0u8; 0]).unwrap();
    assert!(gm.write_at(u64::MAX, &[0, 1]).is_err());
    assert!(gm.write_at(4095, &[0, 1]).is_err());
    assert!(recorder.0.lock().is_empty());
}

// xtask-fmt allow-target-arch cpu-intrinsic
#[cfg(target_arch = "x86_64")]
#[test]
fn native_atomic_writes() {
    let recorder = Arc::new(Recorder::default());
    let gm = GuestMemory::new(
        "atomic",
        Observed {
            backing: AlignedHeapMemory::new(4096),
            tracker: WriteTracker::new(recorder.clone()),
        },
    );
    assert_eq!(
        gm.atomic(8, 8, crate::AtomicOperation::FetchAdd, 9, 0)
            .unwrap(),
        crate::AtomicResult::Value(0)
    );
    assert_eq!(gm.read_plain::<u64>(8).unwrap(), 9);
    assert_eq!(*recorder.0.lock(), [8..16]);
}

struct Fallback {
    bytes: AlignedHeapMemory,
    fail: bool,
    panic_after_write: bool,
    pause: Option<(mpsc::SyncSender<()>, Mutex<mpsc::Receiver<()>>)>,
}

impl Fallback {
    fn new(fail: bool) -> Self {
        Self {
            bytes: AlignedHeapMemory::new(4096),
            fail,
            panic_after_write: false,
            pause: None,
        }
    }
}

// SAFETY: no public mapping is exposed, and copies use the inner allocation.
unsafe impl GuestMemoryAccess for Fallback {
    fn mapping(&self) -> Option<NonNull<u8>> {
        None
    }

    fn max_address(&self) -> u64 {
        4096
    }

    unsafe fn write_fallback(
        &self,
        address: u64,
        src: *const u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        if let Some((entered, release)) = &self.pause {
            entered.send(()).unwrap();
            release.lock().recv().unwrap();
        }
        let count = if self.fail { len.min(2) } else { len };
        // SAFETY: GuestMemory validates the range, and the caller provides src.
        unsafe {
            trycopy::try_copy(
                src,
                self.bytes.mapping().unwrap().as_ptr().add(address as usize),
                count,
            )
        }
        .unwrap();
        assert!(!self.panic_after_write, "backing panic after partial write");
        if self.fail {
            Err(GuestMemoryBackingError::other(
                address + count as u64,
                crate::NotMapped,
            ))
        } else {
            Ok(())
        }
    }

    fn fill_fallback(
        &self,
        address: u64,
        value: u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        // SAFETY: the temporary buffer is readable for the entire call.
        unsafe { self.write_fallback(address, vec![value; len].as_ptr(), len) }
    }
}

#[test]
fn fallback_unwind_notifies_and_releases_gate() {
    let recorder = Arc::new(Recorder::default());
    let tracker = WriteTracker::new(recorder.clone());
    let mut backing = Fallback::new(true);
    backing.panic_after_write = true;
    let backing = Arc::new(backing);
    let gm = GuestMemory::new(
        "unwinding-fallback",
        Observed {
            backing: backing.clone(),
            tracker: tracker.clone(),
        },
    );
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gm.write_at(10, &[3; 5])));
    assert!(result.is_err());
    tracker.synchronize(|| {
        assert_eq!(backing.bytes[10].load(Ordering::Relaxed), 3);
        assert_eq!(backing.bytes[11].load(Ordering::Relaxed), 3);
        assert_eq!(backing.bytes[12].load(Ordering::Relaxed), 0);
        assert_eq!(*recorder.0.lock(), [10..15]);
    });
}

#[test]
fn fallback_partial_errors_and_multi_region_translation() {
    let recorder = Arc::new(Recorder::default());
    let tracker = WriteTracker::new(recorder.clone());
    let backing = Arc::new(Fallback::new(true));
    let gm = GuestMemory::new_multi_region(
        "fallback-multi",
        8192,
        vec![
            Some(Observed {
                backing: backing.clone(),
                tracker: tracker.clone(),
            }),
            Some(Observed {
                backing: backing.clone(),
                tracker: tracker.with_offset(0x10000).unwrap(),
            }),
        ],
    )
    .unwrap();
    assert!(gm.write_at(8192 + 10, &[3; 5]).is_err());
    assert_eq!(backing.bytes[10].load(Ordering::Relaxed), 3);
    assert_eq!(backing.bytes[11].load(Ordering::Relaxed), 3);
    assert_eq!(backing.bytes[12].load(Ordering::Relaxed), 0);
    let subrange = gm.subrange(8192 + 1, 100, true).unwrap();
    let nested = subrange.clone().subrange(3, 50, true).unwrap();
    assert!(nested.fill_at(2, 7, 5).is_err());
    assert_eq!(backing.bytes[6].load(Ordering::Relaxed), 7);
    assert_eq!(*recorder.0.lock(), [0x1000a..0x1000f, 0x10006..0x1000b]);
}

#[test]
fn mapped_multi_region_nested_unaligned_clones() {
    let recorder = Arc::new(Recorder::default());
    let tracker = WriteTracker::new(recorder.clone());
    let gm = GuestMemory::new_multi_region(
        "mapped-multi",
        8192,
        vec![
            None,
            Some(Observed {
                backing: AlignedHeapMemory::new(4096),
                tracker: tracker.with_offset(9000).unwrap(),
            }),
        ],
    )
    .unwrap();
    gm.clone().write_at(8192 + 2, &[8; 2]).unwrap();
    let subrange = gm.subrange(8193, 100, true).unwrap();
    let nested = subrange.subrange(7, 50, true).unwrap();
    nested.clone().write_plain(3, &17u8).unwrap();
    assert_eq!(gm.read_plain::<u8>(8192 + 11).unwrap(), 17);
    assert_eq!(*recorder.0.lock(), [9002..9004, 9011..9012]);
}

#[test]
fn partial_mapped_fault_notifies_before_error_returns() {
    let recorder = Arc::new(Recorder::default());
    let mapping = Arc::new(SparseMapping::new(8192).unwrap());
    mapping.alloc(0, 4096).unwrap();
    let gm = GuestMemory::new(
        "prefix-fault",
        Observed {
            backing: mapping.clone(),
            tracker: WriteTracker::new(recorder.clone()),
        },
    );
    assert!(gm.write_at(4096 - 64, &[0x5a; 128]).is_err());
    let mut prefix = [0; 64];
    gm.read_at(4096 - 64, &mut prefix).unwrap();
    assert_eq!(prefix, [0x5a; 64]);
    assert_eq!(*recorder.0.lock(), [4032..4160]);
}

#[test]
fn observed_views_deny_all_pointer_exposure() {
    struct NoRange;
    impl<'a> crate::LockedRange<'a> for NoRange {
        fn push_sub_range(&mut self, _: &'a [AtomicU8]) {
            panic!("observed views must not expose locked ranges");
        }
    }
    let gm = GuestMemory::new(
        "no-pointers",
        Observed {
            backing: AlignedHeapMemory::new(8192),
            tracker: WriteTracker::new(Arc::new(Recorder::default())),
        },
    );
    let range = gm.subrange(0, 4096, true).unwrap();
    for view in [&gm, &range] {
        assert!(!view.supports_user_lock());
        assert!(!view.supports_kernel_lock());
        assert!(view.full_mapping().is_none());
        assert!(view.sharing().is_none());
        assert!(view.iova(0).is_none());
        assert!(view.inner_buf().is_none());
        for access in [AccessType::Read, AccessType::Write] {
            assert!(view.lock_user_gpns(access, &[0]).is_err());
            assert!(view.lock_kernel_gpns(access, &[0]).is_err());
            assert!(
                view.lock_range(access, PagedRange::new(0, 1, &[0]).unwrap(), NoRange)
                    .is_err()
            );
        }
    }
}

#[test]
fn translated_overflow_is_rejected_without_writing_or_notifying() {
    let recorder = Arc::new(Recorder::default());
    let tracker = WriteTracker::new(recorder.clone())
        .with_offset(u64::MAX - 2)
        .unwrap();
    assert!(tracker.with_offset(3).is_err());
    assert!(tracker.notify_write(1, 2).is_err());
    tracker.notify_write(u64::MAX, 0).unwrap();
    let backing = Arc::new(AlignedHeapMemory::new(4096));
    let gm = GuestMemory::new(
        "overflow",
        Observed {
            backing: backing.clone(),
            tracker,
        },
    );
    assert!(gm.write_at(1, &[1, 2]).is_err());
    assert!(gm.subrange(3, 1, false).is_err());
    assert_eq!(backing[1].load(Ordering::Relaxed), 0);
    assert!(recorder.0.lock().is_empty());
}

#[test]
fn synchronize_waits_for_write_and_callback() {
    struct PausedObserver {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        completed: AtomicBool,
    }
    impl WriteObserver for PausedObserver {
        fn notify_write(&self, _: Range<u64>) {
            self.entered.send(()).unwrap();
            self.release.lock().recv().unwrap();
            self.completed.store(true, Ordering::SeqCst);
        }
    }
    let (in_write, writing) = mpsc::sync_channel(0);
    let (release_write, write_released) = mpsc::sync_channel(0);
    let (in_callback, callback) = mpsc::sync_channel(0);
    let (release_callback, callback_released) = mpsc::sync_channel(0);
    let observer = Arc::new(PausedObserver {
        entered: in_callback,
        release: Mutex::new(callback_released),
        completed: AtomicBool::new(false),
    });
    let tracker = WriteTracker::new(observer.clone());
    let mut backing = Fallback::new(false);
    backing.pause = Some((in_write, Mutex::new(write_released)));
    let gm = GuestMemory::new(
        "paused",
        Observed {
            backing,
            tracker: tracker.clone(),
        },
    );
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| gm.write_at(0, &[1]).unwrap());
        writing.recv().unwrap();
        assert!(tracker.inner.gate.try_write().is_none());
        let (started, registering) = mpsc::sync_channel(0);
        let registration_tracker = &tracker;
        let registration_observer = &observer;
        let registration = scope.spawn(move || {
            started.send(()).unwrap();
            registration_tracker
                .synchronize(|| assert!(registration_observer.completed.load(Ordering::SeqCst)));
        });
        registering.recv().unwrap();
        release_write.send(()).unwrap();
        callback.recv().unwrap();
        assert!(tracker.inner.gate.try_write().is_none());
        release_callback.send(()).unwrap();
        registration.join().unwrap();
        writer.join().unwrap();
    });
}

#[test]
fn racing_writer_invalidates_registration() {
    struct Validity(AtomicBool);
    impl WriteObserver for Validity {
        fn notify_write(&self, _: Range<u64>) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let validity = Arc::new(Validity(AtomicBool::new(false)));
    let tracker = WriteTracker::new(validity.clone());
    let gm = GuestMemory::new(
        "registration",
        Observed {
            backing: AlignedHeapMemory::new(4096),
            tracker: tracker.clone(),
        },
    );
    std::thread::scope(|scope| {
        let (started, writing) = mpsc::sync_channel(0);
        let writer = tracker.synchronize(|| {
            let gm = &gm;
            let writer = scope.spawn(move || {
                started.send(()).unwrap();
                gm.write_at(0, &[1]).unwrap();
            });
            writing.recv().unwrap();
            validity.0.store(true, Ordering::SeqCst);
            assert_eq!(gm.read_plain::<u8>(0).unwrap(), 0);
            writer
        });
        writer.join().unwrap();
    });
    assert!(!validity.0.load(Ordering::SeqCst));
    assert_eq!(gm.read_plain::<u8>(0).unwrap(), 1);
}
