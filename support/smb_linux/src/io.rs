// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// UNSAFETY: SQEs reference owned operation state; native syscalls use retained descriptors.
#![expect(unsafe_code)]

use async_channel::{Receiver, Sender};
use io_uring::{opcode, types};
use pal_async::driver::Driver;
use smb::provider::RequestContext;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

pub(crate) struct Io {
    driver: Arc<dyn Driver>,
    workers: Arc<Workers>,
    pub submitted: AtomicU64,
}

struct Workers {
    available: Receiver<()>,
    returned: Sender<()>,
}

struct Permit(Arc<Workers>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.returned.try_send(()).expect("one token per worker");
    }
}

fn cancelled() -> io::Error {
    io::Error::from_raw_os_error(libc::ECANCELED)
}

pub(crate) fn check(request: &RequestContext) -> io::Result<()> {
    if request.is_cancelled() {
        Err(cancelled())
    } else {
        Ok(())
    }
}

impl Io {
    pub fn new(driver: Arc<dyn Driver>, workers: usize) -> io::Result<Self> {
        if workers == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero workers"));
        }
        for op in [
            opcode::OpenAt2::CODE,
            opcode::OpenAt::CODE,
            opcode::Close::CODE,
            opcode::Statx::CODE,
            opcode::Read::CODE,
            opcode::Write::CODE,
            opcode::Fsync::CODE,
        ] {
            if !driver.io_uring_probe(op) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("required io_uring opcode {op} is unavailable"),
                ));
            }
        }
        let (returned, available) = async_channel::bounded(workers);
        for _ in 0..workers {
            returned.try_send(()).expect("initial worker tokens");
        }
        Ok(Self {
            driver,
            workers: Arc::new(Workers {
                available,
                returned,
            }),
            submitted: AtomicU64::new(0),
        })
    }

    /// # Safety
    ///
    /// The outer operation must own every SQE-referenced allocation and descriptor
    /// through completion, including leaking those inputs if its future is leaked.
    async unsafe fn submit(&self, entry: io_uring::squeue::Entry) -> io::Result<i32> {
        let driver = self.driver.clone();
        self.submitted.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The outer operation owns the SQE's referenced state and drains this future.
        unsafe { driver.io_uring_submit(entry).await }
    }

    pub async fn worker<T: Send + 'static>(
        &self,
        request: &RequestContext,
        work: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        use futures::FutureExt;
        check(request)?;
        let mut available = std::pin::pin!(self.workers.available.recv().fuse());
        let mut cancelled = std::pin::pin!(request.cancelled().fuse());
        futures::select! {
            result = available => result.expect("worker queue remains open"),
            () = cancelled => return Err(crate::io::cancelled()),
        }
        let permit = Permit(self.workers.clone());
        check(request)?;
        // The job, not its awaiting future, owns the slot and native inputs.
        blocking::unblock(move || {
            let _permit = permit;
            work()
        })
        .await
    }

    pub async fn open_root(
        &self,
        path: CString,
        request: &RequestContext,
    ) -> io::Result<Arc<File>> {
        check(request)?;
        let how = types::OpenHow::new()
            .flags((libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64)
            .resolve(RESOLVE_NO_MAGICLINKS);
        let entry = opcode::OpenAt2::new(types::Fd(libc::AT_FDCWD), path.as_ptr(), &how).build();
        // SAFETY: `path` and `how` remain owned until submission completes.
        let fd = unsafe { self.submit(entry).await? };
        // SAFETY: A successful OPENAT2 CQE transfers ownership of this descriptor.
        Ok(Arc::new(unsafe { File::from_raw_fd(fd) }))
    }

    pub async fn open(
        &self,
        parent: Arc<File>,
        name: CString,
        flags: i32,
        mode: u32,
        request: &RequestContext,
    ) -> io::Result<Arc<File>> {
        check(request)?;
        let how = types::OpenHow::new()
            .flags((flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64)
            .mode(u64::from(mode))
            .resolve(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS);
        let entry =
            opcode::OpenAt2::new(types::Fd(parent.as_raw_fd()), name.as_ptr(), &how).build();
        // SAFETY: The operation owns the parent, name and open parameters through completion.
        let fd = unsafe { self.submit(entry).await? };
        // SAFETY: A successful OPENAT2 CQE transfers ownership of this descriptor.
        Ok(Arc::new(unsafe { File::from_raw_fd(fd) }))
    }

    pub async fn reopen(
        &self,
        file: Arc<File>,
        flags: i32,
        request: &RequestContext,
    ) -> io::Result<Arc<File>> {
        check(request)?;
        let name = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .expect("descriptor path has no NUL");
        let entry = opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), name.as_ptr())
            .flags(flags | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK)
            .build();
        // SAFETY: `file` pins the already confined object; only this trusted proc path is followed.
        let fd = unsafe { self.submit(entry).await? };
        // SAFETY: A successful OPENAT CQE transfers ownership of this descriptor.
        Ok(Arc::new(unsafe { File::from_raw_fd(fd) }))
    }

    pub async fn stat(&self, file: Arc<File>, request: &RequestContext) -> io::Result<libc::statx> {
        check(request)?;
        // SAFETY: statx consists entirely of integer fields and padding.
        let mut stat = Box::new(unsafe { std::mem::zeroed::<libc::statx>() });
        let entry = opcode::Statx::new(
            types::Fd(file.as_raw_fd()),
            c"".as_ptr(),
            std::ptr::from_mut(&mut *stat).cast(),
        )
        .flags(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW)
        .mask(libc::STATX_BASIC_STATS | libc::STATX_BTIME)
        .build();
        // SAFETY: The output box and file remain owned through completion.
        unsafe { self.submit(entry).await? };
        Ok(*stat)
    }

    pub async fn read(
        &self,
        file: Arc<File>,
        offset: u64,
        length: u32,
        request: &RequestContext,
    ) -> io::Result<Vec<u8>> {
        check(request)?;
        let mut data = vec![0; length as usize];
        let entry = opcode::Read::new(types::Fd(file.as_raw_fd()), data.as_mut_ptr(), length)
            .offset(offset)
            .build();
        // SAFETY: The owned output buffer and file survive the CQE.
        let count = unsafe { self.submit(entry).await? };
        data.truncate(count as usize);
        Ok(data)
    }

    pub async fn write(
        &self,
        file: Arc<File>,
        offset: u64,
        data: Vec<u8>,
        request: &RequestContext,
    ) -> io::Result<usize> {
        check(request)?;
        let length = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write too large"))?;
        let entry = opcode::Write::new(types::Fd(file.as_raw_fd()), data.as_ptr(), length)
            .offset(offset)
            .build();
        // SAFETY: The owned input buffer and file survive the CQE.
        Ok(unsafe { self.submit(entry).await? } as usize)
    }

    pub async fn flush(&self, file: Arc<File>, request: &RequestContext) -> io::Result<()> {
        check(request)?;
        let entry = opcode::Fsync::new(types::Fd(file.as_raw_fd())).build();
        // SAFETY: The operation owns the descriptor through completion.
        unsafe { self.submit(entry).await? };
        Ok(())
    }

    pub async fn close(&self, file: Arc<File>) -> io::Result<()> {
        let file = match Arc::try_unwrap(file) {
            Ok(file) => file,
            Err(shared) => {
                drop(shared);
                return Ok(());
            }
        };
        let fd = file.into_raw_fd();
        let entry = opcode::Close::new(types::Fd(fd)).build();
        // SAFETY: Ownership of the descriptor transfers to this retained CLOSE operation.
        unsafe { self.submit(entry).await? };
        Ok(())
    }

    pub async fn truncate(
        &self,
        file: Arc<File>,
        length: u64,
        request: &RequestContext,
    ) -> io::Result<()> {
        if self.driver.io_uring_probe(opcode::Ftruncate::CODE) {
            check(request)?;
            let entry = opcode::Ftruncate::new(types::Fd(file.as_raw_fd()), length).build();
            // SAFETY: The operation owns the descriptor through completion.
            unsafe { self.submit(entry).await? };
            Ok(())
        } else {
            self.worker(request, move || file.set_len(length)).await
        }
    }

    pub async fn mkdir(
        &self,
        parent: Arc<File>,
        name: CString,
        request: &RequestContext,
    ) -> io::Result<()> {
        check(request)?;
        let entry = opcode::MkDirAt::new(types::Fd(parent.as_raw_fd()), name.as_ptr())
            .mode(0o777)
            .build();
        // SAFETY: The operation owns the parent and single-component name.
        unsafe { self.submit(entry).await? };
        Ok(())
    }

    pub async fn unlink(
        &self,
        parent: Arc<File>,
        name: CString,
        directory: bool,
        request: &RequestContext,
    ) -> io::Result<()> {
        check(request)?;
        let entry = opcode::UnlinkAt::new(types::Fd(parent.as_raw_fd()), name.as_ptr())
            .flags(if directory { libc::AT_REMOVEDIR } else { 0 })
            .build();
        // SAFETY: The operation owns the parent and single-component name.
        unsafe { self.submit(entry).await? };
        Ok(())
    }

    pub async fn rename(
        &self,
        source: (Arc<File>, CString),
        destination: (Arc<File>, CString),
        replace: bool,
        request: &RequestContext,
    ) -> io::Result<()> {
        check(request)?;
        let entry = opcode::RenameAt::new(
            types::Fd(source.0.as_raw_fd()),
            source.1.as_ptr(),
            types::Fd(destination.0.as_raw_fd()),
            destination.1.as_ptr(),
        )
        .flags(if replace { 0 } else { libc::RENAME_NOREPLACE })
        .build();
        // SAFETY: Both pinned parents and component names survive the CQE.
        unsafe { self.submit(entry).await? };
        Ok(())
    }

    pub async fn readlink(&self, file: Arc<File>, request: &RequestContext) -> io::Result<Vec<u8>> {
        self.worker(request, move || {
            let mut data = vec![0; 4096];
            // SAFETY: AT_EMPTY_PATH-style readlinkat reads this pinned O_PATH symlink.
            let size = unsafe {
                libc::readlinkat(
                    file.as_raw_fd(),
                    c"".as_ptr(),
                    data.as_mut_ptr().cast(),
                    data.len(),
                )
            };
            if size < 0 {
                return Err(io::Error::last_os_error());
            }

            if size as usize == data.len() {
                return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
            }
            data.truncate(size as usize);
            Ok(data)
        })
        .await
    }

    pub async fn directory_hint(
        &self,
        root: Arc<File>,
        path: CString,
        request: &RequestContext,
    ) -> io::Result<bool> {
        check(request)?;
        let how = types::OpenHow::new()
            .flags((libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64)
            .resolve(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS);
        let entry = opcode::OpenAt2::new(types::Fd(root.as_raw_fd()), path.as_ptr(), &how).build();
        // SAFETY: Inspection is rooted at the pinned export; owned parameters survive the CQE.
        match unsafe { self.submit(entry).await } {
            Ok(fd) => {
                // SAFETY: A successful OPENAT2 CQE transfers ownership of this descriptor.
                drop(unsafe { File::from_raw_fd(fd) });
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(
                        libc::ENOENT
                            | libc::ENOTDIR
                            | libc::EACCES
                            | libc::EPERM
                            | libc::EXDEV
                            | libc::ELOOP
                    )
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub async fn permissions(
        &self,
        file: Arc<File>,
        request: &RequestContext,
    ) -> io::Result<(bool, bool, bool)> {
        self.worker(request, move || {
            let mut allowed = [false; 3];
            for (slot, mode) in allowed.iter_mut().zip([libc::R_OK, libc::W_OK, libc::X_OK]) {
                // SAFETY: The retained descriptor is checked without following a link target.
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_faccessat2,
                        file.as_raw_fd(),
                        c"".as_ptr(),
                        mode,
                        libc::AT_EMPTY_PATH | libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if result == 0 {
                    *slot = true;
                } else {
                    let error = io::Error::last_os_error();
                    if !matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM))
                        && !(mode == libc::W_OK && error.raw_os_error() == Some(libc::EROFS))
                    {
                        return Err(error);
                    }
                }
            }
            Ok((allowed[0], allowed[1], allowed[2]))
        })
        .await
    }

    pub async fn filesystem(
        &self,
        file: Arc<File>,
        request: &RequestContext,
    ) -> io::Result<libc::statfs> {
        self.worker(request, move || {
            // SAFETY: statfs contains integer fields and padding; fstatfs writes a complete value.
            let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
            // SAFETY: The descriptor and writable output are owned by this worker.
            if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(stat)
        })
        .await
    }

    pub async fn times(
        &self,
        file: Arc<File>,
        times: [libc::timespec; 2],
        request: &RequestContext,
    ) -> io::Result<()> {
        self.worker(request, move || {
            // SAFETY: AT_EMPTY_PATH updates the retained descriptor, without pathname lookup.
            if unsafe {
                libc::utimensat(
                    file.as_raw_fd(),
                    c"".as_ptr(),
                    times.as_ptr(),
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
        .await
    }

    pub async fn list(
        &self,
        file: Arc<File>,
        request: &RequestContext,
    ) -> io::Result<Vec<CString>> {
        let directory = self
            .reopen(file, libc::O_RDONLY | libc::O_DIRECTORY, request)
            .await?;
        self.worker(request, move || {
            let mut names = Vec::new();
            let mut data = [0u8; 8192];
            loop {
                // SAFETY: getdents64 writes only into the supplied bounded buffer.
                let size = unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        directory.as_raw_fd(),
                        data.as_mut_ptr(),
                        data.len(),
                    )
                };
                if size < 0 {
                    return Err(io::Error::last_os_error());
                }
                if size == 0 {
                    return Ok(names);
                }
                let mut remaining = &data[..size as usize];
                while !remaining.is_empty() {
                    if remaining.len() < 20 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "short dirent"));
                    }
                    let length = u16::from_ne_bytes([remaining[16], remaining[17]]) as usize;
                    if length < 20 || length > remaining.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid dirent length",
                        ));
                    }
                    let name =
                        CStr::from_bytes_until_nul(&remaining[19..length]).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "unterminated dirent")
                        })?;
                    if name != c"." && name != c".." {
                        if names.len() == 65536 {
                            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
                        }
                        names.push(name.to_owned());
                    }
                    remaining = &remaining[length..];
                }
            }
        })
        .await
    }
}
