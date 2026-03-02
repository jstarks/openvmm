// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build a cpio newc initrd from an agent binary.

use std::io;
use std::io::Write;

/// Build a cpio newc archive containing the given binary as `/init`.
pub fn build_initrd(agent_binary: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_cpio_entry(&mut buf, "init", 0o100755, agent_binary, 1);
    write_cpio_trailer(&mut buf);
    buf
}

/// Write a cpio newc archive to a file, containing the given binary as `/init`.
pub fn write_initrd(mut writer: impl Write, agent_binary: &[u8]) -> io::Result<()> {
    let data = build_initrd(agent_binary);
    writer.write_all(&data)
}

fn write_cpio_entry(buf: &mut Vec<u8>, name: &str, mode: u32, data: &[u8], ino: u32) {
    let name_with_nul_len = name.len() + 1;
    let header = format!(
        "070701\
         {ino:08X}\
         {mode:08X}\
         {uid:08X}\
         {gid:08X}\
         {nlink:08X}\
         {mtime:08X}\
         {filesize:08X}\
         {devmajor:08X}\
         {devminor:08X}\
         {rdevmajor:08X}\
         {rdevminor:08X}\
         {namesize:08X}\
         {check:08X}",
        ino = ino,
        mode = mode,
        uid = 0,
        gid = 0,
        nlink = 1,
        mtime = 0,
        filesize = data.len(),
        devmajor = 0,
        devminor = 0,
        rdevmajor = 0,
        rdevminor = 0,
        namesize = name_with_nul_len,
        check = 0,
    );
    buf.extend(header.as_bytes());
    buf.extend(name.as_bytes());
    buf.push(0); // null terminator
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf.extend(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

fn write_cpio_trailer(buf: &mut Vec<u8>) {
    write_cpio_entry(buf, "TRAILER!!!", 0, &[], 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initrd_structure() {
        let fake_binary = b"#!/bin/sh\necho hello\n";
        let data = build_initrd(fake_binary);
        let magic = std::str::from_utf8(&data[..6]).unwrap();
        assert_eq!(magic, "070701");
        assert!(data.windows(4).any(|w| w == b"init"));
        assert!(data.windows(10).any(|w| w == b"TRAILER!!!"));
    }
}
