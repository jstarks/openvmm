// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// UNSAFETY: Native calls use retained handles and owned, correctly sized buffers.
#![expect(unsafe_code)]

use pal::windows::{ObjectAttributes, UnicodeStringRef};
use pal_async::driver::Driver;
use pal_async::windows::overlapped::{CustomNt, OverlappedFile};
use smb::provider::Metadata;
use smb::security::SecurityDescriptor;
use smb::spec::Status;
use std::cell::UnsafeCell;
use std::fs::File;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;
use windows_sys::Wdk::Storage::FileSystem as nt;
use windows_sys::Wdk::System::SystemServices as ss;
use windows_sys::Win32::Foundation::{OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE};
use windows_sys::Win32::Storage::FileSystem as fs;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

struct Completion(UnsafeCell<IO_STATUS_BLOCK>);

impl Completion {
    fn new() -> Self {
        let mut iosb = IO_STATUS_BLOCK::default();
        iosb.Anonymous.Status = windows_sys::Win32::Foundation::STATUS_PENDING;
        Self(UnsafeCell::new(iosb))
    }

    fn as_ptr(&self) -> *mut IO_STATUS_BLOCK {
        self.0.get()
    }

    fn finish(&self, mut result: i32) -> Result<(), Status> {
        // Even a normally synchronous information operation must retain its
        // stack buffers if a filesystem/filter returns pending. This runs only
        // on a bounded worker, and does not rely on file-handle signaling.
        while result == windows_sys::Win32::Foundation::STATUS_PENDING {
            // SAFETY: IO_STATUS_BLOCK begins with aligned NTSTATUS storage.
            result = unsafe { &*self.0.get().cast::<AtomicI32>() }.load(Ordering::Acquire);
            if result == windows_sys::Win32::Foundation::STATUS_PENDING {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        status(result)
    }

    fn information(&self) -> usize {
        // SAFETY: Called only after finish has observed native completion.
        unsafe { (*self.0.get()).Information }
    }
}

pub(crate) fn status(value: i32) -> Result<(), Status> {
    if value >= 0 {
        Ok(())
    } else {
        Err(Status(value as u32))
    }
}

pub(crate) struct Create {
    pub access: u32,
    pub sharing: u32,
    pub disposition: u32,
    pub options: u32,
    pub attributes: u32,
}

pub(crate) fn open(
    parent: Option<&File>,
    name: &[u16],
    create: &Create,
) -> Result<(File, u32), Status> {
    let name = UnicodeStringRef::new(name).ok_or(Status::OBJECT_NAME_INVALID)?;
    let mut attributes = ObjectAttributes::new();
    attributes
        .name(&name)
        .attributes(OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE);
    if let Some(parent) = parent {
        attributes.root(parent.as_handle());
    }
    let mut handle = null_mut();
    let iosb = Completion::new();
    // SAFETY: Names and attributes are borrowed through this synchronous
    // create, and success transfers a new native handle to File.
    unsafe {
        iosb.finish(nt::NtCreateFile(
            &mut handle,
            create.access,
            attributes.as_ptr(),
            iosb.as_ptr(),
            null(),
            create.attributes,
            create.sharing,
            create.disposition,
            create.options,
            null(),
            0,
        ))?;
        Ok((File::from_raw_handle(handle), iosb.information() as u32))
    }
}

pub(crate) fn root(path: &Path) -> Result<File, Status> {
    let path = pal::windows::dos_to_nt_path(path).map_err(|_| Status::OBJECT_NAME_INVALID)?;
    use pal::windows::AsUnicodeStringRef;
    let (file, _) = open(
        None,
        path.as_unicode_string_ref().as_slice(),
        &Create {
            access: fs::FILE_READ_ATTRIBUTES,
            sharing: fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            disposition: nt::FILE_OPEN,
            options: nt::FILE_DIRECTORY_FILE,
            attributes: 0,
        },
    )?;
    let mut buffer = [0u64; 64];
    let iosb = Completion::new();
    // SAFETY: The aligned output holds the entire returned filesystem name.
    unsafe {
        iosb.finish(nt::NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            iosb.as_ptr(),
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            nt::FileFsAttributeInformation,
        ))?;
        let info = &*buffer.as_ptr().cast::<nt::FILE_FS_ATTRIBUTE_INFORMATION>();
        let offset = offset_of!(nt::FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
        let name = wide_name(
            &buffer,
            iosb.information(),
            offset,
            info.FileSystemNameLength,
        )?;
        if name != "NTFS" {
            return Err(Status::NOT_SUPPORTED);
        }
        let mut device = ss::FILE_FS_DEVICE_INFORMATION::default();
        let iosb = Completion::new();
        iosb.finish(nt::NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            iosb.as_ptr(),
            std::ptr::from_mut(&mut device).cast(),
            size_of_val(&device) as u32,
            nt::FileFsDeviceInformation,
        ))?;
        if device.Characteristics & ss::FILE_REMOTE_DEVICE != 0 {
            return Err(Status::NOT_SUPPORTED);
        }
    }
    check_directory(&file)?;
    Ok(file)
}

trait Information: Default {
    const CLASS: nt::FILE_INFORMATION_CLASS;
}

macro_rules! information {
    ($($ty:ty => $class:expr),* $(,)?) => {$(
        impl Information for $ty {
            const CLASS: nt::FILE_INFORMATION_CLASS = $class;
        }
    )*};
}

information! {
    nt::FILE_STAT_INFORMATION => nt::FileStatInformation,
    nt::FILE_ACCESS_INFORMATION => nt::FileAccessInformation,
    nt::FILE_ALIGNMENT_INFORMATION => nt::FileAlignmentInformation,
    nt::FILE_EA_INFORMATION => nt::FileEaInformation,
    nt::FILE_CASE_SENSITIVE_INFORMATION => nt::FileCaseSensitiveInformation,
}

fn query<T: Information>(file: &File) -> Result<T, Status> {
    let mut info = T::default();
    let iosb = Completion::new();
    // SAFETY: The sealed Information implementations pair each layout and class.
    unsafe {
        iosb.finish(nt::NtQueryInformationFile(
            file.as_raw_handle(),
            iosb.as_ptr(),
            std::ptr::from_mut(&mut info).cast(),
            size_of::<T>() as u32,
            T::CLASS,
        ))?;
    }
    Ok(info)
}

pub(crate) fn check_directory(file: &File) -> Result<(), Status> {
    let info: nt::FILE_CASE_SENSITIVE_INFORMATION = query(file)?;
    if info.Flags != 0 {
        Err(Status::NOT_SUPPORTED)
    } else {
        Ok(())
    }
}

fn wide_name(buffer: &[u64], used: usize, offset: usize, bytes: u32) -> Result<String, Status> {
    let end = offset
        .checked_add(bytes as usize)
        .ok_or(Status::INTERNAL_ERROR)?;
    if !bytes.is_multiple_of(2)
        || end > used
        || used > size_of_val(buffer)
        || !offset.is_multiple_of(2)
    {
        return Err(Status::INTERNAL_ERROR);
    }
    // SAFETY: All ranges and UTF-16 alignment are checked above.
    let name = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
            bytes as usize / 2,
        )
    };
    String::from_utf16(name).map_err(|_| Status::OBJECT_NAME_INVALID)
}

pub(crate) fn component(file: &File) -> Result<String, Status> {
    let mut buffer = vec![0u64; 8192];
    let iosb = Completion::new();
    // SAFETY: The aligned output holds a maximum-length NT filename.
    unsafe {
        iosb.finish(nt::NtQueryInformationFile(
            file.as_raw_handle(),
            iosb.as_ptr(),
            buffer.as_mut_ptr().cast(),
            size_of_val(buffer.as_slice()) as u32,
            nt::FileNameInformation,
        ))?;
        let info = &*buffer.as_ptr().cast::<nt::FILE_NAME_INFORMATION>();
        let name = wide_name(
            &buffer,
            iosb.information(),
            offset_of!(nt::FILE_NAME_INFORMATION, FileName),
            info.FileNameLength,
        )?;
        Ok(name.rsplit('\\').next().unwrap_or("").to_owned())
    }
}

pub(crate) fn metadata(file: &File, path: String) -> Result<Metadata, Status> {
    let info: nt::FILE_STAT_INFORMATION = query(file)?;
    let access: nt::FILE_ACCESS_INFORMATION = query(file)?;
    let alignment: nt::FILE_ALIGNMENT_INFORMATION = query(file)?;
    let ea: nt::FILE_EA_INFORMATION = query(file)?;
    Ok(Metadata {
        stream_name: None,
        id: info.FileId as u64,
        id128: None,
        name: path.rsplit('\\').next().unwrap_or("").to_owned(),
        path,
        short_name: None,
        attributes: info.FileAttributes,
        reparse_tag: info.ReparseTag,
        created: info.CreationTime as u64,
        accessed: info.LastAccessTime as u64,
        written: info.LastWriteTime as u64,
        changed: info.ChangeTime as u64,
        size: u64::try_from(info.EndOfFile).map_err(|_| Status::INTERNAL_ERROR)?,
        allocation_size: u64::try_from(info.AllocationSize).map_err(|_| Status::INTERNAL_ERROR)?,
        compression: None,
        number_of_links: info.NumberOfLinks,
        extended_attributes_length: ea.EaSize,
        alignment_requirement: alignment.AlignmentRequirement,
        delete_pending: standard(file)?.DeletePending,
        maximal_access: info.EffectiveAccess,
        granted_access: access.AccessFlags,
    })
}

information! {
    nt::FILE_STANDARD_INFORMATION => nt::FileStandardInformation,
}

fn standard(file: &File) -> Result<nt::FILE_STANDARD_INFORMATION, Status> {
    query(file)
}

pub(crate) fn is_directory(file: &File) -> Result<bool, Status> {
    Ok(standard(file)?.Directory)
}

pub(crate) fn list(directory: &File) -> Result<Vec<String>, Status> {
    check_directory(directory)?;
    let mut buffer = [0u64; 1024];
    let mut names = Vec::new();
    let mut bytes = 0;
    let mut restart = true;
    loop {
        let iosb = Completion::new();
        // SAFETY: This unassociated directory handle has serialized enumeration.
        // The worker retains the aligned output until completion, including pending.
        let result = unsafe {
            nt::NtQueryDirectoryFile(
                directory.as_raw_handle(),
                null_mut(),
                None,
                null(),
                iosb.as_ptr(),
                buffer.as_mut_ptr().cast(),
                size_of_val(&buffer) as u32,
                nt::FileNamesInformation,
                true,
                null(),
                restart,
            )
        };
        match iosb.finish(result) {
            Err(Status::NO_MORE_FILES) => return Ok(names),
            result => result?,
        }
        restart = false;
        // SAFETY: A successful single-entry query returns this fixed prefix.
        let info = unsafe { &*buffer.as_ptr().cast::<nt::FILE_NAMES_INFORMATION>() };
        let name = wide_name(
            &buffer,
            iosb.information(),
            offset_of!(nt::FILE_NAMES_INFORMATION, FileName),
            info.FileNameLength,
        )?;
        if name == "." || name == ".." {
            continue;
        }
        bytes += name.len();
        if names.len() == 4096 || bytes > 1024 * 1024 {
            return Err(Status::INSUFFICIENT_RESOURCES);
        }
        names.push(name);
    }
}

pub(crate) fn set_len(file: &File, length: u64) -> Result<(), Status> {
    let info = ss::FILE_END_OF_FILE_INFORMATION {
        EndOfFile: length.try_into().map_err(|_| Status::INVALID_PARAMETER)?,
    };
    let iosb = Completion::new();
    // SAFETY: This synchronous information class takes the supplied fixed layout.
    unsafe {
        iosb.finish(nt::NtSetInformationFile(
            file.as_raw_handle(),
            iosb.as_ptr(),
            std::ptr::from_ref(&info).cast(),
            size_of_val(&info) as u32,
            nt::FileEndOfFileInformation,
        ))
    }
}

pub(crate) fn flush(file: &File) -> Result<(), Status> {
    let iosb = Completion::new();
    // SAFETY: NtFlushBuffersFile waits synchronously with a retained handle.
    unsafe { iosb.finish(nt::NtFlushBuffersFile(file.as_raw_handle(), iosb.as_ptr())) }
}

pub(crate) fn overlapped(driver: &dyn Driver, file: File) -> std::io::Result<OverlappedFile> {
    // SAFETY: The fresh file has not been duplicated or used for asynchronous I/O.
    unsafe { OverlappedFile::new(driver, file) }
}

pub(crate) fn query_security(file: &File, information: u32) -> Result<SecurityDescriptor, Status> {
    let mut buffer = vec![0u8; 1024];
    loop {
        let mut needed = 0;
        // SAFETY: The synchronous call owns its output through completion.
        let result = unsafe {
            nt::NtQuerySecurityObject(
                file.as_raw_handle(),
                information,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut needed,
            )
        };
        if result == windows_sys::Win32::Foundation::STATUS_BUFFER_TOO_SMALL {
            if needed as usize <= buffer.len() || needed > 256 * 1024 {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            buffer.resize(needed as usize, 0);
            continue;
        }
        status(result)?;
        let bytes = buffer
            .get(..needed as usize)
            .ok_or(Status::INTERNAL_ERROR)?;
        return SecurityDescriptor::decode(bytes).map_err(|_| Status::NOT_SUPPORTED);
    }
}

pub(crate) fn read(file: &OverlappedFile, offset: i64, data: Vec<u8>) -> CustomNt<Vec<u8>> {
    // SAFETY: The kernel references only PAL-owned status and data allocations.
    // NtReadFile captures the offset before returning.
    unsafe {
        file.custom_nt(data, |handle, data, overlapped| {
            nt::NtReadFile(
                handle,
                null_mut(),
                None,
                overlapped.cast(),
                overlapped.cast(),
                data.as_mut_ptr().cast(),
                data.len() as u32,
                &offset,
                null(),
            )
        })
    }
}

pub(crate) fn write(file: &OverlappedFile, offset: i64, data: Vec<u8>) -> CustomNt<Vec<u8>> {
    // SAFETY: The kernel references only PAL-owned status and data allocations.
    // NtWriteFile captures the offset before returning.
    unsafe {
        file.custom_nt(data, |handle, data, overlapped| {
            nt::NtWriteFile(
                handle,
                null_mut(),
                None,
                overlapped.cast(),
                overlapped.cast(),
                data.as_ptr().cast(),
                data.len() as u32,
                &offset,
                null(),
            )
        })
    }
}

#[cfg(test)]
pub(crate) fn set_case_sensitive(file: &File, enabled: bool) -> Result<(), Status> {
    let info = nt::FILE_CASE_SENSITIVE_INFORMATION {
        Flags: u32::from(enabled),
    };
    let iosb = Completion::new();
    // SAFETY: The fixed layout and synchronous information class match.
    unsafe {
        iosb.finish(nt::NtSetInformationFile(
            file.as_raw_handle(),
            iosb.as_ptr(),
            std::ptr::from_ref(&info).cast(),
            size_of_val(&info) as u32,
            nt::FileCaseSensitiveInformation,
        ))
    }
}

#[cfg(test)]
pub(crate) fn set_junction(file: &File, target: &Path) -> Result<(), Status> {
    use pal::windows::AsUnicodeStringRef;
    let target = pal::windows::dos_to_nt_path(target).unwrap();
    let name = target.as_unicode_string_ref().as_slice();
    let length = u16::try_from(name.len() * 2).unwrap();
    let mut buffer = Vec::new();
    buffer.extend_from_slice(
        &windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes(),
    );
    for field in [length + 12, 0, 0, length, length + 2, 0] {
        buffer.extend_from_slice(&field.to_le_bytes());
    }
    for character in name.iter().chain(&[0, 0]) {
        buffer.extend_from_slice(&character.to_le_bytes());
    }
    let iosb = Completion::new();
    // SAFETY: The unassociated handle and complete mount-point buffer are
    // retained until the native filesystem control finishes.
    unsafe {
        iosb.finish(nt::NtFsControlFile(
            file.as_raw_handle(),
            null_mut(),
            None,
            null(),
            iosb.as_ptr(),
            windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            null_mut(),
            0,
        ))
    }
}
