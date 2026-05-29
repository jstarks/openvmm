// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build a minimal FAT32 CIDATA disk image containing pipette.exe.

use anyhow::Context;
use fatfs::FormatVolumeOptions;
use fatfs::FsOptions;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::ops::Range;
use std::path::Path;

const SECTOR_SIZE: u64 = 512;
const DISK_SIZE: u64 = 64 * 1024 * 1024; // 64 MB

/// Build a raw GPT + FAT32 disk image containing `pipette.exe` at the given
/// output path.
pub fn build_cidata_disk(output: &Path, pipette_path: &Path) -> anyhow::Result<()> {
    let mut file = fs_err::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(output)
        .context("failed to create CIDATA image")?;

    file.set_len(DISK_SIZE)
        .context("failed to set CIDATA image size")?;

    let partition_range = build_gpt(&mut file).context("failed to build GPT")?;

    let mut partition =
        fscommon::StreamSlice::new(&mut file, partition_range.start, partition_range.end)
            .context("failed to create partition slice")?;

    build_fat32(&mut partition, pipette_path).context("failed to build FAT32")?;

    Ok(())
}

fn build_gpt(file: &mut (impl Read + Write + Seek)) -> anyhow::Result<Range<u64>> {
    let mut gpt = gptman::GPT::new_from(file, SECTOR_SIZE, guid::Guid::new_random().into())
        .context("failed to create GPT")?;

    gptman::GPT::write_protective_mbr_into(file, SECTOR_SIZE)
        .context("failed to write protective MBR")?;

    // Basic data partition.
    gpt[1] = gptman::GPTPartitionEntry {
        partition_type_guid: guid::guid!("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").into(),
        unique_partition_guid: guid::Guid::new_random().into(),
        starting_lba: gpt.header.first_usable_lba,
        ending_lba: gpt.header.last_usable_lba,
        attribute_bits: 0,
        partition_name: "CIDATA".into(),
    };

    gpt.write_into(file).context("failed to write GPT")?;

    let start = gpt[1].starting_lba * SECTOR_SIZE;
    let size = (gpt[1].ending_lba - gpt[1].starting_lba) * SECTOR_SIZE;
    Ok(start..start + size)
}

fn build_fat32(file: &mut (impl Read + Write + Seek), pipette_path: &Path) -> anyhow::Result<()> {
    fatfs::format_volume(
        &mut *file,
        FormatVolumeOptions::new()
            .volume_label(*b"pipette    ")
            .fat_type(fatfs::FatType::Fat32),
    )
    .context("failed to format FAT32")?;

    let fs = fatfs::FileSystem::new(file, FsOptions::new()).context("failed to open FAT32 fs")?;

    {
        let mut dest = fs
            .root_dir()
            .create_file("pipette.exe")
            .context("failed to create pipette.exe on CIDATA")?;

        let mut src = fs_err::File::open(pipette_path).context("failed to open pipette binary")?;

        std::io::copy(&mut src, &mut dest).context("failed to copy pipette binary")?;
        dest.flush().context("failed to flush pipette.exe")?;
    }

    fs.unmount().context("failed to unmount FAT32")?;

    Ok(())
}
