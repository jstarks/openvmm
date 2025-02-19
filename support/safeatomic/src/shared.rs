use core::cell::UnsafeCell;
use core::fmt::Debug;
use core::ops::Deref;
use core::ops::Index;
use core::sync::atomic::Ordering;
use zerocopy::FromBytes;

#[repr(transparent)]
pub struct Shared<T: ?Sized>(UnsafeCell<T>);

impl<T: Debug> Debug for Shared<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.read(), f)
    }
}

impl<T: Debug> Debug for Shared<[T]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self.as_slice(), f)
    }
}

impl<T: ?Sized> Shared<T> {
    pub fn new(value: T) -> Self
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
        T: Sized,
    {
        todo!()
    }

    pub fn load(&self, ordering: Ordering) -> T
    where
        T: Atomic,
    {
        todo!()
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

impl<T> Shared<[T]> {
    pub fn copy_to_slice(&self, slice: &mut [T])
    where
        T: FromBytes,
    {
        todo!()
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

pub struct SharedMut<T: ?Sized>(UnsafeCell<T>);

impl<T: Debug> Debug for SharedMut<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.read(), f)
    }
}

impl<T: Debug> Debug for SharedMut<[T]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self.as_slice(), f)
    }
}

impl<T: ?Sized> SharedMut<T> {
    pub fn new(value: T) -> Self
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
        T: Sized,
    {
        todo!()
    }

    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }

    pub fn as_ptr(&self) -> *mut T {
        self.0.get()
    }

    pub fn store(&self, ordering: Ordering, value: T)
    where
        T: Atomic,
    {
        todo!()
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
}

pub trait Atomic: Sized {}
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

impl<T> SharedMut<[T]> {
    pub fn copy_from_slice(&self, slice: &[T]) {
        todo!()
    }

    pub fn fill(&self, value: T) {
        todo!()
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
}

impl<T: ?Sized> Deref for SharedMut<T> {
    type Target = Shared<T>;

    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}

#[cfg(test)]
mod tests {
    use super::Shared;

    #[test]
    fn test() {
        let mut x = [0; 100];
        let s = unsafe { Shared::from_raw_parts(x.as_ptr(), x.len()) };
        let _x = &s[0];
        let _y = &s[1..5];
    }
}
