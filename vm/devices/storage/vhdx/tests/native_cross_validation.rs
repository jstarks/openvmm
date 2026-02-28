// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 8.1: Native API cross-validation smoke tests.
//!
//! These tests exercise the first interaction between the Rust VHDX parser
//! and the Windows native VHD stack. They are deliberately limited in scope
//! to surface format-level bugs that need to be diagnosed and fixed before
//! writing a full test suite.
//!
//! **All tests are gated with `#[cfg(windows)]`.**
//!
//! ## Format bugs discovered and fixed
//!
//! (Updated as bugs are found during cross-validation.)

#![cfg(windows)]
// UNSAFETY: Windows FFI calls for virtual disk APIs and raw disk I/O.
#![expect(unsafe_code)]

use parking_lot::Mutex;
use std::io;
use std::path::Path;
use std::sync::Arc;
use vhdx::AsyncFile;
use vhdx::ReadRange;
use vhdx::WriteRange;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::Storage::Vhd::ATTACH_VIRTUAL_DISK_FLAG;
use windows::Win32::Storage::Vhd::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER;
use windows::Win32::Storage::Vhd::ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST;
use windows::Win32::Storage::Vhd::AttachVirtualDisk;
use windows::Win32::Storage::Vhd::CREATE_VIRTUAL_DISK_FLAG_NONE;
use windows::Win32::Storage::Vhd::CREATE_VIRTUAL_DISK_PARAMETERS;
use windows::Win32::Storage::Vhd::CREATE_VIRTUAL_DISK_VERSION_2;
use windows::Win32::Storage::Vhd::CreateVirtualDisk;
use windows::Win32::Storage::Vhd::DetachVirtualDisk;
use windows::Win32::Storage::Vhd::OPEN_VIRTUAL_DISK_FLAG_NONE;
use windows::Win32::Storage::Vhd::OPEN_VIRTUAL_DISK_PARAMETERS;
use windows::Win32::Storage::Vhd::OPEN_VIRTUAL_DISK_VERSION_2;
use windows::Win32::Storage::Vhd::OpenVirtualDisk;
use windows::Win32::Storage::Vhd::VIRTUAL_DISK_ACCESS_MASK;
use windows::Win32::Storage::Vhd::VIRTUAL_STORAGE_TYPE;
use windows::Win32::System::IO::GetOverlappedResult;
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Threading::CreateEventW;
use windows::core::PCWSTR;

// ---------------------------------------------------------------------
// StdFile — blocking AsyncFile adapter for integration tests
// ---------------------------------------------------------------------

/// Blocking `AsyncFile` impl backed by `std::fs::File`.
/// Suitable for tests only — all operations block the current thread.
struct StdFile {
    file: Mutex<std::fs::File>,
}

impl StdFile {
    fn open(path: &Path, read_only: bool) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    fn create(path: &Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl AsyncFile for StdFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), io::Error> {
        use std::io::Read;
        use std::io::Seek;
        use std::io::SeekFrom;
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buf)
    }

    async fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), io::Error> {
        use std::io::Seek;
        use std::io::SeekFrom;
        use std::io::Write;
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(buf)
    }

    async fn flush(&self) -> Result<(), io::Error> {
        use std::io::Write;
        let mut file = self.file.lock();
        file.flush()
    }

    async fn file_size(&self) -> Result<u64, io::Error> {
        let file = self.file.lock();
        file.metadata().map(|m| m.len())
    }

    async fn set_file_size(&self, size: u64) -> Result<(), io::Error> {
        let file = self.file.lock();
        file.set_len(size)
    }
}

// ---------------------------------------------------------------------
// Windows Virtual Disk Type Constants
// ---------------------------------------------------------------------

const VIRTUAL_STORAGE_TYPE_DEVICE_VHDX: u32 = 3;

// Microsoft vendor GUID: {EC984AEC-A0F9-47e9-901F-71415A66345B}
const VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT: windows::core::GUID = windows::core::GUID {
    data1: 0xEC984AEC,
    data2: 0xA0F9,
    data3: 0x47e9,
    data4: [0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B],
};

// ---------------------------------------------------------------------
// Path helper
// ---------------------------------------------------------------------

fn to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ---------------------------------------------------------------------
// NativeVhdx — RAII wrapper around Windows virtual disk APIs
// ---------------------------------------------------------------------

struct NativeVhdx {
    handle: HANDLE,
    attached: bool,
}

impl NativeVhdx {
    /// Create a new dynamic VHDX via CreateVirtualDisk.
    fn create_dynamic(path: &Path, size_bytes: u64, block_size: u32, sector_size: u32) -> Self {
        let storage_type = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };

        let wide = to_wide(path);

        let mut params = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_2,
            ..Default::default()
        };
        params.Anonymous.Version2.MaximumSize = size_bytes;
        params.Anonymous.Version2.BlockSizeInBytes = block_size;
        params.Anonymous.Version2.SectorSizeInBytes = sector_size;

        let mut handle = HANDLE::default();

        // SAFETY: All parameters are correctly initialized, wide path is
        // null-terminated, and handle is written by the API on success.
        let result = unsafe {
            CreateVirtualDisk(
                &storage_type,
                PCWSTR(wide.as_ptr()),
                VIRTUAL_DISK_ACCESS_MASK(0),
                None,
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                &params,
                None,
                &mut handle,
            )
        };
        assert!(result.is_ok(), "CreateVirtualDisk failed: {result:?}");

        NativeVhdx {
            handle,
            attached: false,
        }
    }

    /// Open an existing VHDX via OpenVirtualDisk.
    fn open(path: &Path, _read_only: bool) -> Self {
        let storage_type = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };

        let wide = to_wide(path);

        let params = OPEN_VIRTUAL_DISK_PARAMETERS {
            Version: OPEN_VIRTUAL_DISK_VERSION_2,
            ..Default::default()
        };

        let mut handle = HANDLE::default();

        // SAFETY: All parameters are correctly initialized, wide path is
        // null-terminated, and handle is written by the API on success.
        let result = unsafe {
            OpenVirtualDisk(
                &storage_type,
                PCWSTR(wide.as_ptr()),
                VIRTUAL_DISK_ACCESS_MASK(0),
                OPEN_VIRTUAL_DISK_FLAG_NONE,
                Some(&params),
                &mut handle,
            )
        };
        assert!(result.is_ok(), "OpenVirtualDisk failed: {result:?}");

        NativeVhdx {
            handle,
            attached: false,
        }
    }

    /// Attach with NO_LOCAL_HOST for raw byte-level I/O.
    /// With NO_LOCAL_HOST, no PhysicalDrive device is surfaced — instead,
    /// ReadFile/WriteFile work directly on the virtual disk handle.
    /// Panics if attach fails (tests assume elevation).
    fn attach_raw(&mut self) -> RawDiskHandle {
        let flags = ATTACH_VIRTUAL_DISK_FLAG(
            ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST.0 | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER.0,
        );

        // SAFETY: Handle is valid (from Create/OpenVirtualDisk). Flags are valid.
        let result = unsafe { AttachVirtualDisk(self.handle, None, flags, 0, None, None) };
        assert!(result.is_ok(), "AttachVirtualDisk failed: {result:?}");
        self.attached = true;

        // With NO_LOCAL_HOST the virtual disk handle itself supports
        // ReadFile/WriteFile at virtual-disk offsets. No PhysicalDrive path.
        RawDiskHandle {
            handle: self.handle,
            owned: false,
        }
    }
}

impl Drop for NativeVhdx {
    fn drop(&mut self) {
        if self.attached {
            // SAFETY: Handle is valid and was successfully attached.
            let _ = unsafe { DetachVirtualDisk(self.handle, Default::default(), 0) };
            self.attached = false;
        }
        if !self.handle.is_invalid() {
            // SAFETY: Handle is valid (from Create/OpenVirtualDisk).
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

// ---------------------------------------------------------------------
// RawDiskHandle — read/write at byte offsets on attached virtual disk
// ---------------------------------------------------------------------

struct RawDiskHandle {
    handle: HANDLE,
    /// Whether this handle is owned (should be closed on drop).
    /// When borrowed from NativeVhdx (NO_LOCAL_HOST attach), this is false.
    owned: bool,
}

impl RawDiskHandle {
    /// Read `buf.len()` bytes from the raw disk at the given byte offset.
    /// Offset and length must be sector-aligned (multiples of 512).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: Creating a manual-reset event for overlapped I/O.
        let event = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        let mut overlapped: OVERLAPPED = Default::default();
        overlapped.Anonymous.Anonymous.Offset = (offset & 0xFFFF_FFFF) as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        overlapped.hEvent = event;

        let mut bytes_read = 0u32;
        // SAFETY: Handle is valid, buf is valid for buf.len() bytes,
        // overlapped is correctly initialized with event and offset.
        let result = unsafe {
            ReadFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_read),
                Some(&mut overlapped),
            )
        };
        match result {
            Ok(()) => {}
            Err(e) if e.code() == windows::Win32::Foundation::ERROR_IO_PENDING.into() => {
                // ERROR_IO_PENDING — wait for completion.
                // SAFETY: Handle and overlapped are valid; bWait=true blocks.
                unsafe { GetOverlappedResult(self.handle, &overlapped, &mut bytes_read, true) }
                    .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
            }
            Err(e) => {
                // SAFETY: Event handle is valid.
                let _ = unsafe { CloseHandle(event) };
                return Err(io::Error::from_raw_os_error(e.code().0));
            }
        }
        // SAFETY: Event handle is valid.
        let _ = unsafe { CloseHandle(event) };
        Ok(bytes_read as usize)
    }

    #[allow(dead_code)]
    /// Write `data.len()` bytes to the raw disk at the given byte offset.
    /// Offset and length must be sector-aligned (multiples of 512).
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<usize> {
        // SAFETY: Creating a manual-reset event for overlapped I/O.
        let event = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        let mut overlapped: OVERLAPPED = Default::default();
        overlapped.Anonymous.Anonymous.Offset = (offset & 0xFFFF_FFFF) as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        overlapped.hEvent = event;

        let mut bytes_written = 0u32;
        // SAFETY: Handle is valid, data is valid for data.len() bytes,
        // overlapped is correctly initialized with event and offset.
        let result = unsafe {
            WriteFile(
                self.handle,
                Some(data),
                Some(&mut bytes_written),
                Some(&mut overlapped),
            )
        };
        match result {
            Ok(()) => {}
            Err(e) if e.code() == windows::Win32::Foundation::ERROR_IO_PENDING.into() => {
                // ERROR_IO_PENDING — wait for completion.
                // SAFETY: Handle and overlapped are valid; bWait=true blocks.
                unsafe { GetOverlappedResult(self.handle, &overlapped, &mut bytes_written, true) }
                    .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
            }
            Err(e) => {
                // SAFETY: Event handle is valid.
                let _ = unsafe { CloseHandle(event) };
                return Err(io::Error::from_raw_os_error(e.code().0));
            }
        }
        // SAFETY: Event handle is valid.
        let _ = unsafe { CloseHandle(event) };
        Ok(bytes_written as usize)
    }
}

impl Drop for RawDiskHandle {
    fn drop(&mut self) {
        if self.owned && !self.handle.is_invalid() {
            // SAFETY: Handle is valid and owned by this struct.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

// ---------------------------------------------------------------------
// RustVhdx — helper wrapping the Rust VHDX API for test scenarios
// ---------------------------------------------------------------------

struct RustVhdx {
    vhdx: vhdx::VhdxFile<StdFile>,
    /// Separate file handle for data I/O (shared backing path).
    io_file: Arc<StdFile>,
}

impl RustVhdx {
    async fn create(path: &Path, disk_size: u64, block_size: u32) -> Self {
        let file = StdFile::create(path).expect("create backing file");
        let mut params = vhdx::create::CreateParams {
            disk_size,
            block_size,
            ..Default::default()
        };
        vhdx::create::create(&file, &mut params)
            .await
            .expect("vhdx create");
        drop(file);

        // Re-open for use.
        Self::open(path, false).await
    }

    async fn open(path: &Path, read_only: bool) -> Self {
        let file = StdFile::open(path, read_only).expect("open backing file");
        let io_file = Arc::new(StdFile::open(path, read_only).expect("open io file"));
        let vhdx = vhdx::VhdxFile::open(file, read_only)
            .await
            .expect("vhdx open");
        RustVhdx { vhdx, io_file }
    }

    /// Read data at a virtual offset. Returns a Vec<u8> of `len` bytes.
    #[allow(dead_code)]
    async fn read_data(&self, offset: u64, len: u32) -> Vec<u8> {
        let mut ranges = Vec::new();
        let guard = self
            .vhdx
            .resolve_read(offset, len, &mut ranges)
            .await
            .expect("resolve_read");

        let mut result = vec![0u8; len as usize];

        for range in &ranges {
            match range {
                ReadRange::Data {
                    guest_offset,
                    length,
                    file_offset,
                } => {
                    let buf_offset = (*guest_offset - offset) as usize;
                    let buf_len = *length as usize;
                    self.io_file
                        .read_at(*file_offset, &mut result[buf_offset..buf_offset + buf_len])
                        .await
                        .expect("read data from file");
                }
                ReadRange::Zero { .. } | ReadRange::Unmapped { .. } => {
                    // Already zero-initialized.
                }
            }
        }

        drop(guard);
        result
    }

    /// Write data at a virtual offset.
    #[allow(dead_code)]
    async fn write_data(&self, offset: u64, data: &[u8]) {
        let mut ranges = Vec::new();
        let guard = self
            .vhdx
            .resolve_write(offset, data.len() as u32, &mut ranges)
            .await
            .expect("resolve_write");

        for range in &ranges {
            match range {
                WriteRange::Data {
                    guest_offset,
                    length,
                    file_offset,
                } => {
                    let buf_offset = (*guest_offset - offset) as usize;
                    let buf_len = *length as usize;
                    self.io_file
                        .write_at(*file_offset, &data[buf_offset..buf_offset + buf_len])
                        .await
                        .expect("write data to file");
                }
                WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    let zeros = vec![0u8; *length as usize];
                    self.io_file
                        .write_at(*file_offset, &zeros)
                        .await
                        .expect("zero-fill file range");
                }
            }
        }

        guard.complete().await.expect("write complete");
    }

    /// Flush the VHDX file.
    async fn flush(&self) {
        self.vhdx.flush().await.expect("flush");
    }

    /// Close the VHDX (consume self).
    async fn close(self) {
        self.vhdx.flush().await.expect("flush on close");
        drop(self);
    }
}

// =====================================================================
// Test Cases
// =====================================================================

/// Test 1: Native-Create → Rust-Open (Metadata Check)
///
/// Native creates a dynamic VHDX (1 GiB) → close → Rust opens → verify
/// disk geometry matches.
#[pal_async::async_test]
async fn native_create_rust_open_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let vhdx_path = dir.path().join("test.vhdx");

    // Native create: 1 GiB, default block/sector sizes (pass 0 for defaults).
    {
        let _native = NativeVhdx::create_dynamic(&vhdx_path, 1024 * 1024 * 1024, 0, 0);
        // Drop closes the handle.
    }

    // Rust open and verify metadata.
    let rust = RustVhdx::open(&vhdx_path, true).await;

    // Native defaults: 1 GiB disk, typically 32 MiB block size, 512 sector sizes.
    assert_eq!(rust.vhdx.disk_size(), 1024 * 1024 * 1024, "disk_size");
    // The native default block size is typically 32 MiB, but may vary.
    // Just assert it's a power of 2 and > 0.
    let block_size = rust.vhdx.block_size();
    assert!(block_size > 0 && block_size.is_power_of_two(), "block_size");
    // Sector sizes: native defaults to 512 logical, 4096 physical.
    assert_eq!(rust.vhdx.logical_sector_size(), 512, "logical_sector_size");
    assert_eq!(
        rust.vhdx.physical_sector_size(),
        4096,
        "physical_sector_size"
    );

    rust.close().await;
}

/// Test 2: Rust-Create → Native-Open (Open Succeeds)
///
/// Rust creates a dynamic VHDX (1 GiB) → close → native OpenVirtualDisk
/// succeeds.
#[pal_async::async_test]
async fn rust_create_native_open() {
    let dir = tempfile::tempdir().unwrap();
    let vhdx_path = dir.path().join("test.vhdx");

    // Rust create: 1 GiB, 2 MiB block size (Rust default), 512-byte sectors.
    {
        let rust = RustVhdx::create(&vhdx_path, 1024 * 1024 * 1024, 0).await;
        rust.close().await;
    }

    // Native open — this is the most likely test to fail.
    let _native = NativeVhdx::open(&vhdx_path, true);
    // If we get here, the native stack accepted the Rust-created file.
}

/// Test 3: Rust-Create → Native-Attach → Raw-Read Zeros
///
/// Rust creates a small dynamic VHDX (4 MiB, 2 MiB blocks) → close →
/// native opens → attach → raw-read first sector → verify all zeros.
#[pal_async::async_test]
async fn rust_create_native_attach_read_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let vhdx_path = dir.path().join("test.vhdx");

    // Rust create: 4 MiB disk, 2 MiB block size.
    {
        let rust = RustVhdx::create(&vhdx_path, 4 * 1024 * 1024, 2 * 1024 * 1024).await;
        rust.flush().await;
        rust.close().await;
    }

    // Native open + attach.
    let mut native = NativeVhdx::open(&vhdx_path, false);
    let raw = native.attach_raw();

    // Read the first sector (512 bytes) at offset 0.
    let mut buf = vec![0xCCu8; 512];
    let bytes_read = raw.read_at(0, &mut buf).expect("raw read at offset 0");
    assert_eq!(bytes_read, 512, "expected 512 bytes read");

    // A freshly-created, never-written VHDX should return all zeros.
    assert!(buf.iter().all(|&b| b == 0), "first sector should be zeros");
}
