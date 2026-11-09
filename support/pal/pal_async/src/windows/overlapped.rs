// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows overlapped IO support.

use crate::driver::Driver;
use crate::driver::PollImpl;
use crate::waker::WakerList;
use pal::windows::Overlapped;
use pal::windows::SendSyncRawHandle;
use pal::windows::chk_status;
use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::fs::File;
use std::future::Future;
use std::io;
use std::mem::ManuallyDrop;
use std::os::windows::prelude::*;
use std::pin::Pin;
use std::ptr::null;
use std::ptr::null_mut;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use windows_sys::Win32::Foundation::ERROR_IO_PENDING;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Foundation::STATUS_PENDING;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::IO::OVERLAPPED;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// Driver methods for supporting overlapped files.
pub trait OverlappedIoDriver: Unpin {
    /// The handler type.
    type OverlappedIo: 'static + IoOverlapped;

    /// Creates a new overlapped file handler.
    ///
    /// # Safety
    ///
    /// The caller must ensure that they exclusively own `handle`, and that
    /// `handle` stays alive until the new handler is dropped. The file must
    /// not be reused to issue IO without first disassociating it from this
    /// handler by calling [`IoOverlapped::disassociate`].
    unsafe fn new_overlapped_file(&self, handle: RawHandle) -> io::Result<Self::OverlappedIo>;
}

/// Methods for handling overlapped IO.
pub trait IoOverlapped: Unpin + Send + Sync {
    /// Prepares for an overlapped IO.
    fn pre_io(&self);

    /// Notifies that an IO has been issued.
    ///
    /// # Safety
    /// The caller must have called `pre_io`, and `overlapped` must be
    /// associated with an IO that either completed synchronously (`completed`
    /// is `true`) or is pending completion (`completed` is `false`).
    ///
    /// If `completed` is false, the caller must not deallocate `overlapped`
    /// until `overlapped_io_complete` is called for this IO.
    unsafe fn post_io(&self, completed: bool, overlapped: &Overlapped);

    /// Disassociates the file from the overlapped IO handler so that the file
    /// can be reused for other purposes.
    ///
    /// # Panic
    /// This function may panic if there are still pending IO operations
    /// associated with this handler.
    ///
    /// # Safety
    /// The caller must not call `pre_io` or `post_io` after calling this
    /// function.
    unsafe fn disassociate(&mut self);
}

/// A file opened for overlapped IO.
pub struct OverlappedFile {
    inner: PollImpl<dyn IoOverlapped>,
    file: File,
}

impl OverlappedFile {
    /// Prepares `file` for overlapped IO.
    ///
    /// `file` must have been opened with `FILE_FLAG_OVERLAPPED`.
    ///
    /// # Safety
    /// The caller must ensure that they exclusively own the underlying file,
    /// i.e., that the underlying handle has not been duplicated, and that it
    /// won't be used for asynchronous IO outside of this `OverlappedFile` until
    /// [`into_inner`](Self::into_inner) is called.
    pub unsafe fn new(driver: &(impl ?Sized + Driver), file: File) -> io::Result<Self> {
        // SAFETY: `file` is exclusively owned by the caller.
        let inner = unsafe { driver.new_dyn_overlapped_file(file.as_raw_handle())? };
        Ok(Self { inner, file })
    }

    /// Returns the inner file.
    ///
    /// # Panic
    /// This function will panic if the inner file is still in use by pending IO
    /// operations.
    pub fn into_inner(mut self) -> File {
        // SAFETY: `inner` is being dropped here, so no further IO will be issued.
        unsafe { self.inner.disassociate() };
        self.file
    }

    /// Gets the inner file.
    pub fn get(&self) -> &File {
        &self.file
    }

    /// Cancels all IO for this file.
    pub fn cancel(&self) {
        // SAFETY: File handle is owned by self.
        unsafe {
            CancelIoEx(self.file.as_raw_handle(), null_mut());
        }
    }
}

#[derive(Debug)]
struct Io<T> {
    state: IssueState<T>,
}

#[derive(Debug)]
enum IssueState<T> {
    Pending {
        inner: ManuallyDrop<Pin<Box<IoInner<T>>>>,
        handle: SendSyncRawHandle,
    },
    Complete {
        inner: Box<IoInner<T>>,
        result: Result<(), io::Error>,
    },
    Taken,
}

#[repr(C)]
#[derive(Debug)]
struct IoInner<T> {
    overlapped: Overlapped,
    state: Mutex<InnerState>,
    // `buffers` is aliased and potentially mutated by the kernel while the IO
    // is pending, so use `UnsafeCell` to allow interior mutability.
    buffers: UnsafeCell<T>,
    // This structure cannot move while an IO is pending, since the kernel will
    // mutate its contents and keeps a pointer to its location. Prevent it from
    // being accidentally unpinned and moved.
    _pin: std::marker::PhantomPinned,
}

#[derive(Debug)]
enum InnerState {
    None,
    Issued,
    Waiting(Waker),
    Dropped(unsafe fn(*mut ())),
}

impl<T> Io<T> {
    fn issue<F>(file: &OverlappedFile, offset: i64, buffers: T, f: F) -> Self
    where
        F: FnOnce(RawHandle, &mut T, *mut OVERLAPPED) -> io::Result<()>,
    {
        let mut inner = Box::new(IoInner {
            overlapped: Overlapped::new(),
            state: Mutex::new(InnerState::Issued),
            buffers: UnsafeCell::new(buffers),
            _pin: std::marker::PhantomPinned,
        });
        inner.overlapped.set_offset(offset);

        let handle = file.file.as_raw_handle();
        file.inner.pre_io();
        let result = f(handle, inner.buffers.get_mut(), inner.overlapped.as_ptr());
        let completed = result.as_ref().map_or_else(
            |err| err.raw_os_error() != Some(ERROR_IO_PENDING as i32),
            |_| true,
        );
        // SAFETY: `pre_io` has been called with `overlapped` as the target.
        unsafe {
            file.inner.post_io(completed, &inner.overlapped);
        }
        let state = if completed {
            // The IO completed synchronously. If an error was returned, store
            // it because the IO status block is not updated in this case.
            IssueState::Complete { inner, result }
        } else {
            // Pin `inner` and avoid dropping it while it's still possibly in
            // use by the kernel.
            let inner = ManuallyDrop::new(Box::into_pin(inner));
            IssueState::Pending {
                inner,
                handle: SendSyncRawHandle(handle),
            }
        };
        Self { state }
    }

    fn cancel(&mut self) {
        if let IssueState::Pending { handle, inner } = &self.state {
            // SAFETY: the file handle is alive and the overlapped pointer is still valid.
            unsafe {
                CancelIoEx(handle.0, inner.overlapped.as_ptr());
            }
        }
    }

    fn poll_result(&mut self, cx: &mut Context<'_>) -> Poll<BufResult<T>> {
        self.poll_result_with(cx, |result, overlapped| {
            result.and_then(|()| {
                let (status, len) = overlapped.io_status().expect("IO is known to be complete");
                chk_status(status).map(|_| len)
            })
        })
    }

    fn poll_result_with<R>(
        &mut self,
        cx: &mut Context<'_>,
        complete: impl FnOnce(io::Result<()>, &Overlapped) -> R,
    ) -> Poll<(R, T)> {
        let (r, inner) = match &self.state {
            IssueState::Complete { .. } => {
                let IssueState::Complete { result, inner } =
                    std::mem::replace(&mut self.state, IssueState::Taken)
                else {
                    unreachable!()
                };
                (result, inner)
            }
            IssueState::Pending { inner, .. } => {
                let mut state = inner.state.lock();
                match &mut *state {
                    InnerState::None => {
                        drop(state);
                        let IssueState::Pending { inner, .. } =
                            std::mem::replace(&mut self.state, IssueState::Taken)
                        else {
                            unreachable!()
                        };
                        // SAFETY: Since the IO is completed, `inner` is now
                        // exclusively owned so can be unpinned.
                        let inner =
                            unsafe { Pin::into_inner_unchecked(ManuallyDrop::into_inner(inner)) };
                        (Ok(()), inner)
                    }
                    InnerState::Issued => {
                        *state = InnerState::Waiting(cx.waker().clone());
                        return Poll::Pending;
                    }
                    InnerState::Waiting(waker) => {
                        waker.clone_from(cx.waker());
                        return Poll::Pending;
                    }
                    InnerState::Dropped(_) => unreachable!(),
                }
            }
            IssueState::Taken => panic!("polled after completion"),
        };

        let r = complete(r, &inner.overlapped);
        let buffers = inner.buffers.into_inner();
        Poll::Ready((r, buffers))
    }
}

impl<T: IoBufMut> Io<T> {
    fn read(file: &OverlappedFile, offset: i64, buffers: T) -> Self {
        Self::issue(file, offset, buffers, |handle, buffers, overlapped| {
            // SAFETY: calling ReadFile with valid parameters.
            unsafe {
                if ReadFile(
                    handle,
                    buffers.as_mut_ptr().cast(),
                    buffers.len().min(u32::MAX as usize) as u32,
                    null_mut(),
                    overlapped,
                ) != 0
                {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        })
    }
}

impl<T: IoBuf> Io<T> {
    fn write(file: &OverlappedFile, offset: i64, buffers: T) -> Self {
        Self::issue(file, offset, buffers, |handle, buffers, overlapped| {
            // SAFETY: calling WriteFile with valid parameters.
            unsafe {
                if WriteFile(
                    handle,
                    buffers.as_ptr().cast(),
                    buffers.len().min(u32::MAX as usize) as u32,
                    null_mut(),
                    overlapped,
                ) != 0
                {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        })
    }
}

impl<T: IoBufMut, U: IoBufMut> Io<(T, U)> {
    /// # Safety
    /// The caller must ensure the IOCTL is safe to call.
    unsafe fn ioctl(file: &OverlappedFile, code: u32, input: T, output: U) -> Self {
        Self::issue(
            file,
            0,
            (input, output),
            |handle, (input, output), overlapped| {
                // SAFETY: calling DeviceIoControl with valid parameters, according to the caller
                unsafe {
                    if DeviceIoControl(
                        handle,
                        code,
                        input.as_mut_ptr().cast(),
                        input.len() as u32,
                        output.as_mut_ptr().cast(),
                        output.len() as u32,
                        null_mut(),
                        overlapped,
                    ) != 0
                    {
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error())
                    }
                }
            },
        )
    }
}

/// Called when an overlapped IO has completed.
///
/// # Safety
/// The caller must ensure that `overlapped` is a valid pointer to an overlapped
/// structure associated with an IO that has just completed.
pub(crate) unsafe fn overlapped_io_done(overlapped: *mut OVERLAPPED, wakers: &mut WakerList) {
    let inner = overlapped as *const IoInner<()>;
    let old_state = {
        // SAFETY: `inner` is currently shared between this function and the
        // owner of the `Io`.
        let inner = unsafe { &*inner };
        std::mem::replace(&mut *inner.state.lock(), InnerState::None)
    };
    match old_state {
        InnerState::None => unreachable!(),
        InnerState::Issued => {}
        InnerState::Waiting(waker) => wakers.push(waker),
        InnerState::Dropped(drop_fn) => {
            // SAFETY: `inner` is owned (since the original `Io` has been
            // dropped) and `drop_fn` is the correct function to drop it.
            unsafe { drop_fn(inner.cast_mut().cast()) }
        }
    }
}

impl<T> Drop for Io<T> {
    fn drop(&mut self) {
        match &mut self.state {
            IssueState::Taken | IssueState::Complete { .. } => {}
            IssueState::Pending { inner, .. } => {
                // An IO may still be pending.
                let old_state = std::mem::replace(
                    &mut *inner.state.lock(),
                    InnerState::Dropped(|p| {
                        // SAFETY: `p` is owned and is of the correct type.
                        unsafe { drop(Box::from_raw(p.cast::<IoInner<T>>())) };
                    }),
                );
                match old_state {
                    InnerState::None => {
                        // SAFETY: inner is now exclusively owned.
                        unsafe { ManuallyDrop::drop(inner) };
                    }
                    InnerState::Waiting(_) | InnerState::Issued => {
                        // Ensure the IO completes soon so that buffers can be freed.
                        self.cancel();
                    }
                    InnerState::Dropped(_) => unreachable!(),
                }
            }
        }
    }
}

/// A non-movable buffer that owns its storage.
///
/// # Safety
/// The implementor must ensure that the methods are implemented as described.
pub unsafe trait IoBuf {
    /// Returns a stable pointer to the storage.
    fn as_ptr(&self) -> *const u8;
    /// Returns the length of the storage in bytes.
    fn len(&self) -> usize;
}

/// A mutable non-movable buffer that owns its storage.
///
/// # Safety
/// The implementor must ensure that the methods are implemented as described.
pub unsafe trait IoBufMut: IoBuf {
    /// Returns a stable mutable pointer to the storage.
    fn as_mut_ptr(&mut self) -> *mut u8;
}

// SAFETY: implementing trait according to requirements.
unsafe impl<T> IoBuf for [T; 0] {
    fn as_ptr(&self) -> *const u8 {
        null()
    }

    fn len(&self) -> usize {
        0
    }
}

// SAFETY: implementing trait according to requirements.
unsafe impl<T> IoBufMut for [T; 0] {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        null_mut()
    }
}

// SAFETY: implementing trait according to requirements.
unsafe impl IoBuf for () {
    fn as_ptr(&self) -> *const u8 {
        null()
    }

    fn len(&self) -> usize {
        0
    }
}

// SAFETY: implementing trait according to requirements.
unsafe impl IoBufMut for () {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        null_mut()
    }
}

// SAFETY: implementing trait according to requirements.
unsafe impl<T: IntoBytes + Immutable + KnownLayout> IoBuf for &'static [T] {
    fn as_ptr(&self) -> *const u8 {
        self.as_bytes().as_ptr()
    }

    fn len(&self) -> usize {
        self.as_bytes().len()
    }
}

// SAFETY: implementing trait according to requirements.
unsafe impl<T: IntoBytes + Immutable + KnownLayout> IoBuf for Vec<T> {
    fn as_ptr(&self) -> *const u8 {
        self.as_bytes().as_ptr()
    }

    fn len(&self) -> usize {
        self.as_bytes().len()
    }
}

// SAFETY: implementing trait according to requirements.
unsafe impl<T: IntoBytes + FromBytes + Immutable + KnownLayout> IoBufMut for Vec<T> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_bytes().as_mut_ptr()
    }
}

impl OverlappedFile {
    /// Reads from the file at `offset` into `buffer`.
    pub fn read_at<T: IoBufMut>(&self, offset: u64, buffer: T) -> Read<T> {
        Read(Io::read(self, offset as i64, buffer))
    }

    /// Writes to the file at `offset` from `buffer`.
    pub fn write_at<T: IoBuf>(&self, offset: u64, buffer: T) -> Write<T> {
        Write(Io::write(self, offset as i64, buffer))
    }

    /// Issues an IOCTL to the file.
    ///
    /// # Safety
    /// The caller must ensure the IOCTL is safe to call. This is device and
    /// IOCTL specific.
    pub unsafe fn ioctl<T: IoBufMut, U: IoBufMut>(
        &self,
        code: u32,
        input: T,
        output: U,
    ) -> Ioctl<T, U> {
        // SAFETY: caller ensures IOCTL is safe.
        Ioctl(unsafe { Io::ioctl(self, code, input, output) })
    }

    /// Performs a custom overlapped IO by calling `f`.
    ///
    /// # Safety
    /// The caller must issue the IO in `f` and return its syscall result. The
    /// kernel must only alias memory that is in `buffers`, and only after it
    /// has been moved into its final location (provided to `f` in the second
    /// parameter).
    pub unsafe fn custom<F, T>(&self, buffers: T, f: F) -> Custom<T>
    where
        F: FnOnce(RawHandle, &mut T, *mut OVERLAPPED) -> io::Result<()>,
    {
        Custom(Io::issue(self, 0, buffers, f))
    }

    /// Performs native overlapped I/O without translating its completion status.
    ///
    /// # Safety
    /// The requirements of [`Self::custom`] apply. `f` must issue an NT operation
    /// using `overlapped` as both its completion context and IO_STATUS_BLOCK,
    /// and return the NTSTATUS from that operation.
    pub unsafe fn custom_nt<F, T>(&self, buffers: T, f: F) -> CustomNt<T>
    where
        F: FnOnce(RawHandle, &mut T, *mut OVERLAPPED) -> NTSTATUS,
    {
        CustomNt(Io::issue(
            self,
            0,
            buffers,
            |handle, buffers, overlapped| {
                let status = f(handle, buffers, overlapped);
                if status == STATUS_PENDING {
                    Err(io::Error::from_raw_os_error(ERROR_IO_PENDING as i32))
                } else {
                    // SAFETY: An inline completion no longer aliases this status
                    // block. On immediate failure NT need not have written it.
                    unsafe {
                        (*overlapped).Internal = status as usize;
                        if status as u32 >> 30 == 3 {
                            (*overlapped).InternalHigh = 0;
                        }
                    }
                    Ok(())
                }
            },
        ))
    }
}

/// An IO result that returns the associated buffers.
pub type BufResult<T> = (io::Result<usize>, T);

macro_rules! io {
    ($name:ident, ($($generics:ident),*), $buffers:ty) => {
        /// An IO operation.
        #[derive(Debug)]
        #[must_use]
        pub struct $name<$($generics,)*>(Io<$buffers>);

        impl<$($generics,)*> $name<$($generics,)*> {
            /// Requests that the kernel cancel the IO.
            ///
            /// This does not synchronously cancel the IO. Await the object to
            /// wait for the IO to complete.
            pub fn cancel(&mut self) {
                self.0.cancel()
            }
        }

        impl<$($generics,)*> Future for $name<$($generics,)*> {
            type Output = BufResult<$buffers>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.get_mut().0.poll_result(cx)
            }
        }
    };
}

io!(Read, (T), T);
io!(Write, (T), T);
io!(Ioctl, (T, U), (T, U));
io!(Custom, (T), T);

/// A native operation returning its untranslated status, byte count and buffers.
#[derive(Debug)]
#[must_use]
pub struct CustomNt<T>(Io<T>);

impl<T> CustomNt<T> {
    /// Requests cancellation. Await this operation to observe its actual result.
    pub fn cancel(&mut self) {
        self.0.cancel();
    }
}

impl<T> Future for CustomNt<T> {
    type Output = ((NTSTATUS, usize), T);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().0.poll_result_with(cx, |result, overlapped| {
            assert!(
                result.is_ok(),
                "native issue only returns pending or success"
            );
            overlapped.io_status().expect("IO is known to be complete")
        })
    }
}

#[cfg(test)]
mod tests {
    // UNSAFETY: Test operations retain their buffers through native completion.
    #![expect(unsafe_code)]

    use super::*;
    use crate::DefaultDriver;
    use crate::async_test;
    use crate::windows::pipe::{ListeningPipe, NamedPipeServer};
    use pal::windows::pipe::{Disposition, PipeMode, new_named_pipe};
    use std::fs::OpenOptions;
    use test_with_tracing::test;
    use windows_sys::Wdk::Storage::FileSystem::{NtReadFile, NtWriteFile};
    use windows_sys::Win32::Foundation::{
        STATUS_ACCESS_DENIED, STATUS_CANCELLED, STATUS_END_OF_FILE, STATUS_SUCCESS,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

    fn read(file: &OverlappedFile, offset: Option<i64>, length: usize) -> CustomNt<Vec<u8>> {
        // SAFETY: The native call only aliases the operation's owned storage.
        unsafe {
            file.custom_nt(vec![0; length], |handle, data, overlapped| {
                NtReadFile(
                    handle,
                    null_mut(),
                    None,
                    overlapped.cast(),
                    overlapped.cast(),
                    data.as_mut_ptr().cast(),
                    data.len() as u32,
                    offset.as_ref().map_or(null(), std::ptr::from_ref),
                    null(),
                )
            })
        }
    }

    async fn pair(driver: &DefaultDriver) -> (OverlappedFile, OverlappedFile) {
        let mut name = [0; 16];
        getrandom::fill(&mut name).unwrap();
        let path = format!(r"\\.\pipe\{:x}", u128::from_ne_bytes(name));
        let server = NamedPipeServer::create(&path).unwrap();
        let mut accept = server.accept(driver).unwrap();
        assert!(futures::poll!(&mut accept).is_pending());
        let client = OpenOptions::new()
            .read(true)
            .write(true)
            .attributes(FILE_FLAG_OVERLAPPED)
            .open(&path)
            .unwrap();
        let server = accept.await.unwrap();
        // SAFETY: Each handle is exclusively owned and opened for overlapped I/O.
        unsafe {
            (
                OverlappedFile::new(driver, server).unwrap(),
                OverlappedFile::new(driver, client).unwrap(),
            )
        }
    }

    #[async_test]
    async fn native_inline_errors_and_partial_read(driver: DefaultDriver) {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), b"data").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .attributes(FILE_FLAG_OVERLAPPED)
            .open(temp.path())
            .unwrap();
        // SAFETY: This fresh handle is exclusively owned.
        let file = unsafe { OverlappedFile::new(&driver, file).unwrap() };
        // SAFETY: Native arguments refer only to the owned buffer and status.
        let write = unsafe {
            file.custom_nt(vec![1u8], |handle, data, overlapped| {
                NtWriteFile(
                    handle,
                    null_mut(),
                    None,
                    overlapped.cast(),
                    overlapped.cast(),
                    data.as_ptr().cast(),
                    1,
                    &0,
                    null(),
                )
            })
        };
        let ((status, count), data) = write.await;
        assert_eq!((status, count), (STATUS_ACCESS_DENIED, 0));
        assert_eq!(data, [1]);
        let ((status, count), data) = read(&file, Some(0), 8).await;
        assert_eq!((status, count), (STATUS_SUCCESS, 4));
        assert_eq!(&data[..count], b"data");
        let ((status, count), _) = read(&file, Some(4), 8).await;
        assert_eq!((status, count), (STATUS_END_OF_FILE, 0));
    }

    #[async_test]
    async fn native_pending_cancel_and_retained_operation(driver: DefaultDriver) {
        let (server, client) = pair(&driver).await;
        let mut cancelled = read(&server, None, 8);
        assert!(futures::poll!(&mut cancelled).is_pending());
        cancelled.cancel();
        let ((status, count), data) = cancelled.await;
        assert_eq!((status, count, data.len()), (STATUS_CANCELLED, 0, 8));

        let mut retained = read(&server, None, 8);
        {
            let mut temporary = std::pin::pin!(std::future::poll_fn(|cx| {
                Pin::new(&mut retained).poll(cx)
            }));
            assert!(futures::poll!(&mut temporary).is_pending());
        }
        client.write_at(0, b"ready".as_slice()).await.0.unwrap();
        // Completion won the race: a late cancellation must retain the result.
        retained.cancel();
        let ((status, count), data) = retained.await;
        assert_eq!((status, count), (STATUS_SUCCESS, 5));
        assert_eq!(&data[..count], b"ready");
    }

    #[async_test]
    async fn native_dropped_pending_operation_does_not_consume_next_read(driver: DefaultDriver) {
        let (server, client) = pair(&driver).await;
        let mut dropped = read(&server, None, 8);
        assert!(futures::poll!(&mut dropped).is_pending());
        drop(dropped);
        let mut next = read(&server, None, 8);
        assert!(futures::poll!(&mut next).is_pending());
        client.write_at(0, b"next".as_slice()).await.0.unwrap();
        let ((status, count), data) = next.await;
        assert_eq!((status, count), (STATUS_SUCCESS, 4));
        assert_eq!(&data[..count], b"next");
    }

    #[async_test]
    async fn native_warning_preserves_partial_message_bytes(driver: DefaultDriver) {
        let mut name = [0; 16];
        getrandom::fill(&mut name).unwrap();
        let path = format!(r"\\.\pipe\{:x}", u128::from_ne_bytes(name));
        let pipe = new_named_pipe(
            &path,
            windows_sys::Win32::Foundation::GENERIC_READ
                | windows_sys::Win32::Foundation::GENERIC_WRITE,
            Disposition::Create,
            PipeMode::Message,
        )
        .unwrap();
        let mut accept = ListeningPipe::new(&driver, pipe).unwrap();
        assert!(futures::poll!(&mut accept).is_pending());
        let client = OpenOptions::new().write(true).open(&path).unwrap();
        let server = accept.await.unwrap();
        // SAFETY: The fresh handle has exclusive overlapped ownership.
        let server = unsafe { OverlappedFile::new(&driver, server).unwrap() };
        use std::io::Write;
        (&client).write_all(b"message").unwrap();
        let ((status, count), data) = read(&server, None, 3).await;
        assert_eq!(
            status,
            windows_sys::Win32::Foundation::STATUS_BUFFER_OVERFLOW
        );
        assert_eq!(count, 3);
        assert_eq!(data, b"mes");
        let ((status, count), data) = read(&server, None, 8).await;
        assert_eq!((status, count), (STATUS_SUCCESS, 4));
        assert_eq!(&data[..count], b"sage");
    }
}
