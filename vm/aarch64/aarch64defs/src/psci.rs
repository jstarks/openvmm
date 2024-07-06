use core::ops::Range;
use open_enum::open_enum;

pub const PSCI32: Range<u32> = 0x84000000..0x84000020;
pub const PSCI64: Range<u32> = 0xc4000000..0xc4000020;

open_enum! {
    pub enum PsciCall32: u32 {
        PSCI_VERSION = 0x8400_0000,
        CPU_SUSPEND = 0x8400_0001,
        CPU_OFF = 0x8400_0002,
        CPU_ON = 0x8400_0003,
        AFFINITY_INFO = 0x8400_0004,
        MIGRATE = 0x8400_0005,
        MIGRATE_INFO_TYPE = 0x8400_0006,
        MIGRATE_INFO_UP_CPU = 0x8400_0007,
        SYSTEM_OFF = 0x8400_0008,
        SYSTEM_OFF2 = 0x8400_0015,
        SYSTEM_RESET = 0x8400_0009,
        SYSTEM_RESET2 = 0x8400_0012,
        MEM_PROTECT = 0x8400_0013,
        MEM_PROTECT_CHECK_RANGE = 0x8400_0014,
        PSCI_FEATURES = 0x8400_000a,
        CPU_FREEZE = 0x8400_000b,
        CPU_DEFAULT_SUSPEND = 0x8400_000c,
        NODE_HW_STATE = 0x8400_000d,
        SYSTEM_SUSPEND = 0x8400_000e,
        PSCI_SET_SUSPEND_MODE = 0x8400_000f,
        PSCI_STAT_RESIDENCY = 0x8400_0010,
        PSCI_STAT_COUNT = 0x8400_0011,
    }
}

open_enum! {
    pub enum PsciCall64: u32 {
        CPU_SUSPEND = 0xc400_0001,
        CPU_ON = 0xc400_0003,
        AFFINITY_INFO = 0xc400_0004,
        MIGRATE = 0xc400_0005,
        MIGRATE_INFO_UP_CPU = 0xc400_0007,
        SYSTEM_OFF2 = 0xc400_0015,
        SYSTEM_RESET2 = 0xc400_0012,
        MEM_PROTECT_CHECK_RANGE = 0xc400_0014,
        CPU_DEFAULT_SUSPEND = 0xc400_000c,
        NODE_HW_STATE = 0xc400_000d,
        SYSTEM_SUSPEND = 0xc400_000e,
        PSCI_STAT_RESIDENCY = 0xc400_0010,
        PSCI_STAT_COUNT = 0xc400_0011,
    }
}

open_enum! {
    pub enum PsciError: i32 {
        SUCCESS = 0,
        NOT_SUPPORTED = -1,
        INVALID_PARAMETERS = -2,
        DENIED = -3,
        ALREADY_ON = -4,
        ON_PENDING = -5,
        INTERNAL_FAILURE = -6,
        NOT_PRESENT = -7,
        DISABLED = -8,
        INVALID_ADDRESS = -9,
    }
}
