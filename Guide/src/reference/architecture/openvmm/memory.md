# Memory Management

OpenVMM's memory subsystem is responsible for allocating guest RAM, mapping it
into the hypervisor partition, and providing device emulation code with safe
access to guest memory. The implementation lives primarily in two crates:

- **`guestmem`** — the consumer-facing API (`GuestMemory`, `GuestMemoryAccess`)
- **`membacking`** — the producer-side infrastructure that allocates RAM and
  coordinates mappings

## Key Concepts

### Guest Physical Address (GPA) Space

A VM's GPA space is defined by its `MemoryLayout` and typically contains:

- **RAM regions** — contiguous ranges of guest-visible memory.
- **Device memory** — VRAM, ROM BARs, virtio-fs DAX windows, NVMe CMBs, etc.
- **MMIO holes** — unmapped ranges where accesses trap to the VMM for device
  emulation.

### GuestMemory and GuestMemoryAccess

`GuestMemory` (from the `guestmem` crate) is the handle that device emulation
code uses to read and write guest memory. Under the hood, it wraps a
`GuestMemoryAccess` implementation that provides a host virtual address (VA)
mapping of the guest address space.

The access model is:

1. `GuestMemoryAccess::mapping()` returns a base VA pointer.
2. Add the GPA offset to get a host VA, then do a volatile read/write.
3. If the VA is unmapped or protected, a structured exception / signal triggers
   `page_fault()`, which can lazily populate the mapping and return `Retry`, or
   fail the access.

This design allows the fast path (step 2) to be a single pointer dereference
with no system calls.

## The `membacking` Pipeline

The `membacking` crate implements the full pipeline from RAM allocation through
to hypervisor GPA mapping. The components, in order:

```text
GuestMemoryBuilder
    │
    ├─ allocates RAM (shared section or anonymous pages)
    ├─ creates RegionManager, MappingManager, VaMapper
    │
    ▼
RegionManager
    │
    ├─ tracks regions (RAM, device memory) with priorities
    ├─ resolves overlaps (higher priority wins)
    ├─ propagates active mappings to ──► MappingManager
    └─ propagates map/unmap to ──────► PartitionMapper(s)
                                            │
MappingManager                              │
    │                                       │
    ├─ distributes file-backed mappings     │
    │   to VA mappers on demand             │
    └─ fans out invalidations               │
                                            │
VaMapper ◄──────────────────────────────────┘
    │
    ├─ SparseMapping: contiguous VA for the full GPA space
    ├─ implements GuestMemoryAccess (→ GuestMemory)
    └─ PartitionMapper: maps VA into hypervisor's GPA tables
```

### Regions and Priorities

A **region** is a fixed-size range of GPA space with a priority (0–255). RAM
gets priority 255 (highest); device memory gets priority 0. When regions
overlap, the higher-priority region's data is what the guest sees.

This allows patterns like:

- **VGA RAM window** (0xA0000–0xBFFFF): a separate RAM region that can be
  independently unmapped to expose underlying VGA device MMIO.
- **PAM registers** (0xC0000–0xFFFFF): used by x86 firmware to toggle ROM
  shadow regions between RAM and ROM.

### Mappings

Each region has zero or more **mappings** — bindings from a sub-range of the
region to a `(Mappable, file_offset)` pair. `Mappable` is a cross-platform
wrapper around an OS section handle (Windows) or file descriptor (Linux) that
can be memory-mapped.

The mapping manager distributes these to VA mappers lazily: a VA mapper
requests a mapping only when its `page_fault()` handler detects an unmapped
address.

### The VaMapper

The `VaMapper` is the heart of memory access. It owns a `SparseMapping` (from
`sparse_mmap`) that reserves a contiguous VA range equal to the maximum guest
address. Both RAM and device memory coexist in this single VA space.

The VA mapper implements `GuestMemoryAccess`, so it can be wrapped in
`GuestMemory` for use by device emulation code. It also provides the base VA
pointer that `PartitionMapper` passes to the hypervisor's `map_range()` API.

## RAM Allocation Modes

### File-Backed (Default)

Guest RAM is allocated as a single file-backed section:

- **Windows**: `CreateFileMappingW(INVALID_HANDLE_VALUE, ...)` — backed by the
  system page file.
- **Linux**: `memfd_create()` or equivalent.

The section is sliced into per-region mappings and distributed to VA mappers
via the mapping manager. This mode supports:

- **Multi-process mapping**: The `Mappable` handle can be duplicated to a
  remote process for cross-process WHV mapping.
- **Servicing / migration**: The `SharedMemoryBacking` can be transferred to
  reconstruct the memory manager in a new process.

### Private Anonymous Memory

When `--private-memory` is specified, guest RAM is backed by anonymous pages
directly in the VaMapper's `SparseMapping`:

- **Windows**: `VirtualAlloc2(MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER)`
  during build; `VirtualAlloc(MEM_COMMIT)` for recommit after decommit.
- **Linux**: `mmap(MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED)` — the kernel
  manages lazy backing from the zero page.

Advantages:

- No page file commit charge until pages are actually touched.
- Supports `decommit()` to release physical pages back to the host (for
  balloon / free page reporting).
- Simpler for single-process, single-partition use cases.

Limitations:

- Incompatible with multi-process mapping (no `Mappable` to share).
- Incompatible with servicing (no `SharedMemoryBacking`).
- Incompatible with `x86_legacy_support` (PAM register toggling).

### Platform Differences

| Aspect | Windows | Linux |
|--------|---------|-------|
| Initial commit | Explicit via `alloc_range()` → `VirtualAlloc2` | Kernel-managed (lazy zero page) |
| Page fault on uncommitted VA | WHV delivers `MemoryAccess` exit → VMM calls `commit()` → resume | Kernel handles transparently — no VMM involvement |
| Decommit | `VirtualFree(MEM_DECOMMIT)` — pages return to reserved state | `madvise(MADV_DONTNEED)` — pages released, next access gets zero pages |
| Recommit after decommit | WHV exit → `commit()` via `VirtualAlloc(MEM_COMMIT)` | Automatic (kernel zero page COW) |

## Partition Mapping

`PartitionMapper` bridges the VaMapper's host VA to the hypervisor's guest
physical address tables:

- **WHV** (Windows): `WHvMapGpaRange(partition, host_va, gpa, size, flags)`
- **KVM** (Linux): `KVM_SET_USER_MEMORY_REGION` ioctl

The partition mapper calls `ensure_mapped()` before mapping to pre-populate
the VaMapper's file-backed VA. In private-RAM mode, `ensure_mapped()` results
are discarded — the VA is already committed, and the hypervisor will resolve
faults through the host MMU.

## Device Memory

Device memory (VRAM, ROM BARs, NVMe CMBs, virtio-fs DAX) flows through the
same region manager → mapping manager → VA mapper pipeline as RAM, but at
lower priority. The `DeviceMemoryMapper` implements the `MemoryMapper` trait,
which device backends use to create regions and map file-backed data into them.

Device memory always uses file-backed `Mappable` objects, regardless of
whether guest RAM is private or shared.

## Further Reading

- `guestmem` crate — consumer-facing `GuestMemory` and `GuestMemoryAccess` API
- `membacking` crate — the full memory management pipeline
- `sparse_mmap` crate — low-level VA reservation, placeholder management, and
  cross-platform `mmap` / `VirtualAlloc2` abstractions
