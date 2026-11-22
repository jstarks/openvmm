// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exercise hardware dirty logging with a real guest CPU store.
#![cfg(all(windows, target_arch = "aarch64"))]

#[test]
#[ignore = "requires native ARM64 WHP with dirty tracking"]
fn guest_store_starts_a_new_dirty_epoch() {
    use whp::PartitionProperty;
    use whp::Register64;
    use whp::abi;

    #[repr(align(4096))]
    struct Pages([u8; 8192]);
    let mut pages = Box::new(Pages([0; 8192]));
    // mov x0, #0x1000; str x0, [x0]; ldr x1, [x0, #8192] (unmapped).
    for (slot, word) in pages
        .0
        .chunks_exact_mut(4)
        .zip([0xd2820000u32, 0xf9000000, 0xf9500001])
    {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    let mut cfg = whp::PartitionConfig::new().unwrap();
    cfg.set_property(PartitionProperty::ProcessorCount(1))
        .unwrap();
    cfg.set_property(PartitionProperty::GicParameters(
        abi::WHV_ARM64_IC_PARAMETERS {
            EmulationMode: abi::WHV_ARM64_IC_EMULATION_MODE::GicV3,
            Reserved: 0,
            GicV3Parameters: abi::WHV_ARM64_IC_GIC_V3_PARAMETERS {
                GicdBaseAddress: 0x8000000,
                GitsTranslatorBaseAddress: 0,
                Reserved: 0,
                GicLpiIntIdBits: 0,
                GicPpiOverflowInterruptFromCntv: 20,
                GicPpiPerformanceMonitorsInterrupt: 23,
                Reserved1: [0; 6],
            },
        },
    ))
    .unwrap();
    let p = cfg.create().unwrap();
    let flags =
        abi::WHvMapGpaRangeFlagRead | abi::WHvMapGpaRangeFlagWrite | abi::WHvMapGpaRangeFlagExecute;
    let ptr = pages.0.as_mut_ptr();
    // UNSAFETY: mapping owned test RAM into the WHP partition.
    #[expect(unsafe_code)]
    // SAFETY: the aligned allocation remains live until after the partition
    // drops, including on unwinding, and is not accessed while the VP runs.
    let map = |flags| unsafe { p.map_range(None, ptr, 8192, 0, flags).unwrap() };
    map(flags);
    p.create_vp(0).create().unwrap();
    let vp = p.vp(0);
    vp.set_register(Register64::GicrBaseGpa, 0x8100000).unwrap();
    vp.set_register(Register64::Pc, 0).unwrap();
    vp.set_register(Register64::Cpsr, 0x3c5).unwrap();
    vp.runner().run().unwrap();
    vp.set_register(Register64::Pc, 0).unwrap();
    map(flags | abi::WHvMapGpaRangeFlagTrackDirtyPages);
    p.query_dirty_bitmap(0, 8192, None).unwrap();
    vp.runner().run().unwrap();
    assert_eq!(&pages.0[4096..4104], &4096u64.to_le_bytes());
    let mut bits = [0];
    p.query_dirty_bitmap(0, 8192, Some(&mut bits)).unwrap();
    assert_eq!(bits, [2]);
    p.query_dirty_bitmap(0, 8192, Some(&mut bits)).unwrap();
    assert_eq!(bits, [0]);
    map(flags);
}
