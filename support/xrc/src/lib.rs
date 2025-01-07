#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
pub mod arc {
    pub use parking_lot::Mutex;
    pub use parking_lot::MutexGuard;
    pub use parking_lot::RawMutex;
    pub use parking_lot::RawRwLock;
    pub use parking_lot::RwLock;
    pub use std::sync::Arc;
    pub use std::sync::Weak;
}

pub mod rc {
    // UNSAFETY: needed to implement raw mutex types.
    #![expect(unsafe_code)]

    pub use alloc::rc::Rc as Arc;
    pub use alloc::rc::Weak;
    pub type Mutex<T> = lock_api::Mutex<RawMutex, T>;
    pub type RwLock<T> = lock_api::RwLock<RawRwLock, T>;
    pub type MutexGuard<'a, T> = lock_api::MutexGuard<'a, RawMutex, T>;

    use core::cell::Cell;

    pub struct RawMutex(Cell<bool>);

    unsafe impl lock_api::RawMutex for RawMutex {
        const INIT: Self = Self(Cell::new(false));

        type GuardMarker = lock_api::GuardNoSend;

        fn lock(&self) {
            assert!(!self.0.replace(true));
        }
        fn try_lock(&self) -> bool {
            !self.0.replace(true)
        }
        unsafe fn unlock(&self) {
            assert!(self.0.replace(false));
        }
    }

    pub struct RawRwLock(Cell<isize>);

    unsafe impl lock_api::RawRwLock for RawRwLock {
        const INIT: Self = Self(Cell::new(0));

        type GuardMarker = lock_api::GuardNoSend;

        fn lock_shared(&self) {
            let val = self.0.get();
            assert!(val >= 0, "deadlock");
            self.0.set(val.checked_add(1).unwrap());
        }

        fn try_lock_shared(&self) -> bool {
            if self.0.get() < 0 {
                false
            } else {
                self.lock_shared();
                true
            }
        }

        unsafe fn unlock_shared(&self) {
            let val = self.0.get();
            assert!(val > 0);
            self.0.set(val - 1);
        }

        fn lock_exclusive(&self) {
            let val = self.0.get();
            assert!(val == 0, "deadlock");
            self.0.set(-1);
        }

        fn try_lock_exclusive(&self) -> bool {
            if self.0.get() != 0 {
                false
            } else {
                self.lock_exclusive();
                true
            }
        }

        unsafe fn unlock_exclusive(&self) {
            assert_eq!(self.0.get(), -1);
            self.0.set(0);
        }
    }
}
