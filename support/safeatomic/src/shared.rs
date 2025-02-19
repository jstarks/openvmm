use core::array::TryFromSliceError;
use core::cell::UnsafeCell;
use core::fmt::Debug;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ops::Index;
use core::sync::atomic::Ordering;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

mod primitives {
    use core::sync::atomic::Ordering;

    pub unsafe fn read8(ptr: *const u8) -> u8 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn read16(ptr: *const u16) -> u16 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn read32(ptr: *const u32) -> u32 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn read64(ptr: *const u64) -> u64 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn write8(ptr: *mut u8, value: u8) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn write16(ptr: *mut u16, value: u16) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn write32(ptr: *mut u32, value: u32) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn write64(ptr: *mut u64, value: u64) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn copy(src: *const u8, dst: *mut u8, len: usize) {
        unsafe { core::ptr::copy(src, dst, len) }
    }
    pub unsafe fn fill(dst: *mut u8, len: usize, value: u8) {
        unsafe { core::ptr::write_bytes(dst, value, len) }
    }
    pub unsafe fn load8(ptr: *const u8, ordering: Ordering) -> u8 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn load16(ptr: *const u16, ordering: Ordering) -> u16 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn load32(ptr: *const u32, ordering: Ordering) -> u32 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn load64(ptr: *const u64, ordering: Ordering) -> u64 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn store8(ptr: *mut u8, value: u8, ordering: Ordering) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn store16(ptr: *mut u16, value: u16, ordering: Ordering) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn store32(ptr: *mut u32, value: u32, ordering: Ordering) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn store64(ptr: *mut u64, value: u64, ordering: Ordering) {
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
    pub unsafe fn swap8(ptr: *mut u8, value: u8, ordering: Ordering) -> u8 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn swap16(ptr: *mut u16, value: u16, ordering: Ordering) -> u16 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn swap32(ptr: *mut u32, value: u32, ordering: Ordering) -> u32 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn swap64(ptr: *mut u64, value: u64, ordering: Ordering) -> u64 {
        unsafe { core::ptr::read_volatile(ptr) }
    }
    pub unsafe fn compare_exchange8(
        ptr: *mut u8,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u8, u8> {
        unsafe { Ok(core::ptr::read_volatile(ptr)) }
    }
    pub unsafe fn compare_exchange16(
        ptr: *mut u16,
        current: u16,
        new: u16,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u16, u16> {
        unsafe { Ok(core::ptr::read_volatile(ptr)) }
    }
    pub unsafe fn compare_exchange32(
        ptr: *mut u32,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        unsafe { Ok(core::ptr::read_volatile(ptr)) }
    }
    pub unsafe fn compare_exchange64(
        ptr: *mut u64,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        unsafe { Ok(core::ptr::read_volatile(ptr)) }
    }
}

#[repr(transparent)]
#[derive(Default)]
pub struct Shared<T: ?Sized>(UnsafeCell<T>);

unsafe impl<T: Send + ?Sized> Send for Shared<T> {}
unsafe impl<T: Sync + ?Sized> Sync for Shared<T> {}

impl<T: ?Sized> AsRef<Shared<T>> for Shared<T> {
    fn as_ref(&self) -> &Shared<T> {
        self
    }
}

impl<T: Debug + FromBytes> Debug for Shared<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.read(), f)
    }
}

impl<T: Debug + FromBytes> Debug for Shared<[T]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self.as_slice(), f)
    }
}

impl<T: ?Sized> Shared<T> {
    pub const fn new(value: T) -> Self
    where
        T: Sized,
    {
        Self(UnsafeCell::new(value))
    }

    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.0.into_inner()
    }

    pub fn read(&self) -> T
    where
        T: Sized + FromBytes,
    {
        match size_of::<T>() {
            1 => unsafe { core::mem::transmute_copy(&primitives::read8(self.as_ptr().cast())) },
            2 => unsafe { core::mem::transmute_copy(&primitives::read16(self.as_ptr().cast())) },
            4 => unsafe { core::mem::transmute_copy(&primitives::read32(self.as_ptr().cast())) },
            8 => unsafe { core::mem::transmute_copy(&primitives::read64(self.as_ptr().cast())) },
            _ => unsafe {
                let mut v = MaybeUninit::<T>::uninit();
                primitives::copy(self.as_ptr().cast(), v.as_mut_ptr().cast(), size_of::<T>());
                v.assume_init()
            },
        }
    }

    pub fn load(&self, ordering: Ordering) -> T
    where
        T: Atomic,
    {
        match size_of::<T>() {
            1 => unsafe {
                core::mem::transmute_copy(&primitives::load8(self.as_ptr().cast(), ordering))
            },
            2 => unsafe {
                core::mem::transmute_copy(&primitives::load16(self.as_ptr().cast(), ordering))
            },
            4 => unsafe {
                core::mem::transmute_copy(&primitives::load32(self.as_ptr().cast(), ordering))
            },
            8 => unsafe {
                core::mem::transmute_copy(&primitives::load64(self.as_ptr().cast(), ordering))
            },
            _ => unreachable!(),
        }
    }

    pub fn as_ptr(&self) -> *const T {
        self.0.get()
    }

    pub fn try_cast<U: FromBytes>(&self) -> Option<&Shared<U>> {
        if size_of_val(self) != size_of::<U>() {
            return None;
        }
        if !self.as_ptr().cast::<U>().is_aligned() {
            return None;
        }
        Some(unsafe { Shared::from_raw(self.as_ptr().cast()) })
    }

    pub fn try_cast_slice<U>(&self) -> Option<&Shared<[U]>> {
        if size_of_val(self) % size_of::<U>() != 0 {
            return None;
        }
        if !self.as_ptr().cast::<U>().is_aligned() {
            return None;
        }
        let len = size_of_val(self) / size_of::<U>();
        Some(unsafe { Shared::from_raw_parts(self.as_ptr().cast(), len) })
    }

    pub unsafe fn from_raw<'a>(ptr: *const T) -> &'a Shared<T> {
        unsafe { core::mem::transmute(ptr) }
    }

    pub fn as_bytes(&self) -> &Shared<[u8]> {
        let slice = core::ptr::slice_from_raw_parts(self.as_ptr().cast::<u8>(), size_of_val(self));
        unsafe { &*(slice as *const Shared<[u8]>) }
    }
}

impl<T, const N: usize> Shared<[T; N]> {
    pub fn as_array_ref(&self) -> &[Shared<T>; N] {
        unsafe { core::mem::transmute(self) }
    }

    pub fn as_slice(&self) -> &Shared<[T]> {
        Shared::from_slice(self.as_array_ref())
    }
}

impl<T> Shared<[T]> {
    pub fn copy_to_slice(&self, slice: &mut [T])
    where
        T: FromBytes,
    {
        unsafe {
            primitives::copy(
                self.as_ptr().cast(),
                slice.as_mut_ptr().cast(),
                size_of_val(self),
            )
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub unsafe fn from_raw_parts<'a>(ptr: *const T, len: usize) -> &'a Shared<[T]> {
        let slice = core::ptr::slice_from_raw_parts(ptr, len);
        unsafe { Self::from_raw(slice) }
    }

    pub fn from_slice(slice: &[Shared<T>]) -> &Shared<[T]> {
        unsafe { core::mem::transmute(slice) }
    }

    pub fn as_slice(&self) -> &[Shared<T>] {
        unsafe { core::mem::transmute(self) }
    }
}

macro_rules! index {
    ($b:ty) => {
        impl<T> Index<$b> for Shared<[T]> {
            type Output = Shared<[T]>;

            fn index(&self, index: $b) -> &Self::Output {
                Self::from_slice(&self.as_slice()[index])
            }
        }
        impl<T> Index<$b> for SharedMut<[T]> {
            type Output = SharedMut<[T]>;

            fn index(&self, index: $b) -> &Self::Output {
                Self::from_slice(&self.as_slice()[index])
            }
        }
    };
}

index!(core::ops::Range<usize>);
index!(core::ops::RangeFrom<usize>);
index!(core::ops::RangeTo<usize>);
index!(core::ops::RangeToInclusive<usize>);
index!(core::ops::RangeInclusive<usize>);
index!(core::ops::RangeFull);

impl<T> Index<usize> for Shared<[T]> {
    type Output = Shared<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T> Index<usize> for SharedMut<[T]> {
    type Output = SharedMut<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

#[derive(Default)]
pub struct SharedMut<T: ?Sized>(UnsafeCell<T>);

impl<'a, T, const N: usize> TryFrom<&'a SharedMut<[T]>> for &'a SharedMut<[T; N]> {
    type Error = TryFromSliceError;

    fn try_from(value: &'a SharedMut<[T]>) -> Result<Self, Self::Error> {
        let v = <&[SharedMut<T>; N]>::try_from(value.as_slice())?;
        Ok(SharedMut::from_array_ref(v))
    }
}

unsafe impl<T: Send + ?Sized> Send for SharedMut<T> {}
unsafe impl<T: Sync + ?Sized> Sync for SharedMut<T> {}

impl<T: Debug + FromBytes> Debug for SharedMut<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.read(), f)
    }
}

impl<T: Debug + FromBytes> Debug for SharedMut<[T]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self.as_slice(), f)
    }
}

impl<T: ?Sized> SharedMut<T> {
    pub const fn new(value: T) -> Self
    where
        T: Sized,
    {
        Self(UnsafeCell::new(value))
    }

    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.0.into_inner()
    }

    pub fn write(&self, value: T)
    where
        T: Sized + IntoBytes,
    {
        self.write_ref(&value);
    }

    fn write_ref(&self, value: &T)
    where
        T: Sized + IntoBytes,
    {
        match size_of::<T>() {
            1 => unsafe {
                primitives::write8(self.as_ptr().cast(), core::mem::transmute_copy(value))
            },
            2 => unsafe {
                primitives::write16(self.as_ptr().cast(), core::mem::transmute_copy(value))
            },
            4 => unsafe {
                primitives::write32(self.as_ptr().cast(), core::mem::transmute_copy(value))
            },
            8 => unsafe {
                primitives::write64(self.as_ptr().cast(), core::mem::transmute_copy(value))
            },
            _ => unsafe {
                primitives::copy(
                    core::ptr::from_ref(value).cast(),
                    self.as_ptr().cast(),
                    size_of::<T>(),
                )
            },
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }

    pub fn as_ptr(&self) -> *mut T {
        self.0.get()
    }

    pub fn store(&self, value: T, ordering: Ordering)
    where
        T: Atomic,
    {
        match size_of::<T>() {
            1 => unsafe {
                primitives::store8(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&value),
                    ordering,
                )
            },
            2 => unsafe {
                primitives::store16(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&value),
                    ordering,
                )
            },
            4 => unsafe {
                primitives::store32(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&value),
                    ordering,
                )
            },
            8 => unsafe {
                primitives::store64(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&value),
                    ordering,
                )
            },
            _ => unreachable!(),
        }
    }

    pub fn compare_exchange(
        &self,
        current: T,
        new: T,
        success: Ordering,
        failure: Ordering,
    ) -> Result<T, T>
    where
        T: Atomic,
    {
        match size_of::<T>() {
            1 => unsafe {
                core::mem::transmute_copy(&primitives::compare_exchange8(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&current),
                    core::mem::transmute_copy(&new),
                    success,
                    failure,
                ))
            },
            2 => unsafe {
                core::mem::transmute_copy(&primitives::compare_exchange16(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&current),
                    core::mem::transmute_copy(&new),
                    success,
                    failure,
                ))
            },
            4 => unsafe {
                core::mem::transmute_copy(&primitives::compare_exchange32(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&current),
                    core::mem::transmute_copy(&new),
                    success,
                    failure,
                ))
            },
            8 => unsafe {
                core::mem::transmute_copy(&primitives::compare_exchange64(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&current),
                    core::mem::transmute_copy(&new),
                    success,
                    failure,
                ))
            },
            _ => unreachable!(),
        }
    }

    pub fn fetch_or(&self, value: T, ordering: Ordering) -> T
    where
        T: Atomic,
    {
        let mut current = self.load(Ordering::Relaxed);
        loop {
            match self.compare_exchange(current, current | value, ordering, Ordering::Relaxed) {
                Ok(v) => return v,
                Err(v) => current = v,
            }
        }
    }

    pub fn read(&self) -> T
    where
        T: Sized + FromBytes,
    {
        self.as_ref().read()
    }

    pub fn load(&self, ordering: Ordering) -> T
    where
        T: Atomic,
    {
        self.as_ref().load(ordering)
    }

    pub fn swap(&self, t: T, ordering: Ordering) -> T
    where
        T: Atomic,
    {
        match size_of::<T>() {
            1 => unsafe {
                core::mem::transmute_copy(&primitives::swap8(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&t),
                    ordering,
                ))
            },
            2 => unsafe {
                core::mem::transmute_copy(&primitives::swap16(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&t),
                    ordering,
                ))
            },
            4 => unsafe {
                core::mem::transmute_copy(&primitives::swap32(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&t),
                    ordering,
                ))
            },
            8 => unsafe {
                core::mem::transmute_copy(&primitives::swap64(
                    self.as_ptr().cast(),
                    core::mem::transmute_copy(&t),
                    ordering,
                ))
            },
            _ => unreachable!(),
        }
    }

    pub fn try_cast<U: FromBytes>(&self) -> Option<&SharedMut<U>> {
        if size_of_val(self) != size_of::<U>() {
            return None;
        }
        if !self.as_ptr().cast::<U>().is_aligned() {
            return None;
        }
        Some(unsafe { SharedMut::from_raw(self.as_ptr().cast()) })
    }

    pub fn try_cast_slice<U>(&self) -> Option<&SharedMut<[U]>> {
        if size_of_val(self) % size_of::<U>() != 0 {
            return None;
        }
        if !self.as_ptr().cast::<U>().is_aligned() {
            return None;
        }
        let len = size_of_val(self) / size_of::<U>();
        Some(unsafe { SharedMut::from_raw_parts(self.as_ptr().cast(), len) })
    }

    pub unsafe fn from_raw<'a>(ptr: *mut T) -> &'a SharedMut<T> {
        unsafe { core::mem::transmute(ptr) }
    }

    pub unsafe fn from_raw_mut<'a>(ptr: *mut T) -> &'a mut SharedMut<T> {
        unsafe { core::mem::transmute(ptr) }
    }

    pub fn as_bytes(&self) -> &SharedMut<[u8]> {
        let slice = core::ptr::slice_from_raw_parts(self.as_ptr().cast::<u8>(), size_of_val(self));
        unsafe { &*(slice as *const SharedMut<[u8]>) }
    }
}

pub trait Atomic: Copy + Sized + core::ops::BitOr<Output = Self> {}
impl Atomic for u8 {}
impl Atomic for u16 {}
impl Atomic for u32 {}
impl Atomic for u64 {}
impl Atomic for i8 {}
impl Atomic for i16 {}
impl Atomic for i32 {}
impl Atomic for i64 {}
impl Atomic for usize {}
impl Atomic for isize {}

impl<T, const N: usize> SharedMut<[T; N]> {
    pub fn as_array_ref(&self) -> &[SharedMut<T>; N] {
        unsafe { core::mem::transmute(self) }
    }

    pub fn from_array_ref(slice: &[SharedMut<T>; N]) -> &SharedMut<[T; N]> {
        unsafe { core::mem::transmute(slice) }
    }

    pub fn as_slice(&self) -> &SharedMut<[T]> {
        SharedMut::from_slice(self.as_array_ref())
    }
}

impl<T> SharedMut<[T]> {
    pub fn copy_to_slice(&self, slice: &mut [T])
    where
        T: FromBytes,
    {
        self.as_ref().copy_to_slice(slice);
    }

    pub fn copy_from_slice(&self, slice: &[T])
    where
        T: IntoBytes,
    {
        unsafe {
            primitives::copy(
                slice.as_ptr().cast(),
                self.as_ptr().cast(),
                size_of_val(self),
            )
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn fill(&self, value: T)
    where
        T: IntoBytes,
    {
        match size_of::<T>() {
            1 => unsafe {
                primitives::fill(
                    self.as_ptr().cast(),
                    size_of_val(self),
                    core::mem::transmute_copy(&value),
                )
            },
            _ => {
                for v in self {
                    v.write_ref(&value);
                }
            }
        }
    }

    pub fn as_slice(&self) -> &[SharedMut<T>] {
        unsafe { core::mem::transmute(self) }
    }

    pub fn from_slice(slice: &[SharedMut<T>]) -> &SharedMut<[T]> {
        unsafe { core::mem::transmute(slice) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::mem::transmute(self) }
    }

    pub unsafe fn from_raw_parts<'a>(ptr: *mut T, len: usize) -> &'a SharedMut<[T]> {
        let slice = core::ptr::slice_from_raw_parts_mut(ptr, len);
        unsafe { Self::from_raw(slice) }
    }

    pub unsafe fn from_raw_parts_mut<'a>(ptr: *mut T, len: usize) -> &'a mut SharedMut<[T]> {
        let slice = core::ptr::slice_from_raw_parts_mut(ptr, len);
        unsafe { Self::from_raw_mut(slice) }
    }

    pub fn iter(&self) -> core::slice::Iter<'_, SharedMut<T>> {
        self.as_slice().iter()
    }
}

impl<'a, T> IntoIterator for &'a SharedMut<[T]> {
    type Item = &'a SharedMut<T>;
    type IntoIter = core::slice::Iter<'a, SharedMut<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: ?Sized> AsRef<Shared<T>> for SharedMut<T> {
    fn as_ref(&self) -> &Shared<T> {
        unsafe { core::mem::transmute(self) }
    }
}

impl<T, const N: usize> Deref for SharedMut<[T; N]> {
    type Target = SharedMut<[T]>;

    fn deref(&self) -> &Self::Target {
        SharedMut::from_slice(self.as_array_ref())
    }
}

#[cfg(test)]
mod tests {}
