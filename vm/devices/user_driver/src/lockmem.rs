// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

use crate::memory::MappedDmaTarget;
use anyhow::Context;
use safeatomic::AtomicSliceOps;
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering::Relaxed;
use zerocopy::AsBytes;

const PAGE_SIZE: usize = 4096;

pub struct LockedMemory {
    mapping: Mapping,
    pfns: Vec<u64>,
}

// SAFETY: The result of an mmap is safe to share amongst threads.
unsafe impl Send for Mapping {}
// SAFETY: The result of an mmap is safe to share amongst threads.
unsafe impl Sync for Mapping {}

struct Mapping {
    addr: *mut c_void,
    len: usize,
}

impl Mapping {
    fn new(len: usize) -> std::io::Result<Self> {
        // SAFETY: No file descriptor or address is being passed.
        // The result is being validated.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_LOCKED,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { addr, len })
    }

    fn lock(&self) -> std::io::Result<()> {
        // SAFETY: self contains a valid mmap result.
        if unsafe { libc::mlock(self.addr, self.len) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn pages(&self) -> anyhow::Result<Vec<u64>> {
        let mut pagemap = File::open("/proc/self/pagemap").context("failed to open pagemap")?;
        pagemap
            .seek(SeekFrom::Start((8 * self.addr as usize / PAGE_SIZE) as u64))
            .context("failed to seek")?;
        let n = self.len / PAGE_SIZE;
        let mut pfns = vec![0u64; n];
        pagemap
            .read(pfns.as_bytes_mut())
            .context("failed to read from pagemap")?;
        for pfn in &mut pfns {
            if *pfn & (1 << 63) == 0 {
                anyhow::bail!("page not present in RAM");
            }
            *pfn &= 0x3f_ffff_ffff_ffff;
        }

        // Now validate the pages are correct.
        let mem = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mem")
            .context("failed to open /dev/mem")?;
        let map =
            sparse_mmap::SparseMapping::new(self.len).context("failed to create sparse mapping")?;
        for (i, &pfn) in pfns.iter().enumerate() {
            map.map_file(
                i * PAGE_SIZE,
                PAGE_SIZE,
                mem.file(),
                pfn * PAGE_SIZE as u64,
                true,
            )
            .with_context(|| format!("failed to map page {pfn}"))?;
        }
        let a = unsafe { std::slice::from_raw_parts(self.addr as *const AtomicU8, self.len) };
        let b = map.atomic_slice(0, self.len);
        let mut n = 3u64;
        for (i, (a, b)) in a.iter().zip(b).enumerate() {
            let v = n as u8;
            a.store(v, Relaxed);
            assert_eq!(
                b.load(Relaxed),
                v,
                "mismatch at byte {i} pfn {pfn:#x}",
                pfn = pfns[i / PAGE_SIZE]
            );
            n = n.wrapping_mul(7);
        }
        a.atomic_fill(0);
        Ok(pfns)
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: self contains a valid mmap result.
        if unsafe { libc::munmap(self.addr, self.len) } < 0 {
            panic!("{:?}", std::io::Error::last_os_error());
        }
    }
}

impl LockedMemory {
    pub fn new(len: usize) -> anyhow::Result<Self> {
        if len % PAGE_SIZE != 0 {
            anyhow::bail!("not a page-size multiple");
        }
        let mapping = Mapping::new(len).context("failed to create mapping")?;
        mapping.lock().context("failed to lock mapping")?;
        let pages = mapping.pages()?;
        Ok(Self {
            mapping,
            pfns: pages,
        })
    }
}

// SAFETY: The stored mapping is valid for the lifetime of the LockedMemory.
// It is only unmapped on drop.
unsafe impl MappedDmaTarget for LockedMemory {
    fn base(&self) -> *const u8 {
        self.mapping.addr.cast()
    }

    fn len(&self) -> usize {
        self.mapping.len
    }

    fn pfns(&self) -> &[u64] {
        &self.pfns
    }
}

#[derive(Clone)]
pub struct LockedMemorySpawner;

#[cfg(feature = "vfio")]
impl crate::vfio::VfioDmaBuffer for LockedMemorySpawner {
    fn create_dma_buffer(&self, len: usize) -> anyhow::Result<crate::memory::MemoryBlock> {
        Ok(crate::memory::MemoryBlock::new(LockedMemory::new(len)?))
    }

    /// Restore mapped DMA memory at the same physical location after servicing.
    fn restore_dma_buffer(
        &self,
        _len: usize,
        _base_pfn: u64,
    ) -> anyhow::Result<crate::memory::MemoryBlock> {
        anyhow::bail!("restore not supported for lockmem")
    }
}
