# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'

# Activate an isolated virtual redirector instance, without changing the
# machine's ordinary SMB client signing or authentication policy.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class VsmbGuest {
    [StructLayout(LayoutKind.Sequential)]
    struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)]
    struct Privilege { public uint Count; public Luid Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out SafeFileHandle token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(SafeFileHandle token, bool disableAll,
        ref Privilege privilege, uint length, IntPtr previous, IntPtr returnedLength);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr attributes, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool DefineDosDevice(uint flags, string name, string target);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualFree(IntPtr address, UIntPtr size, uint operation);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadFile(SafeFileHandle handle, IntPtr buffer, uint length, out uint read, IntPtr overlapped);
    [DllImport("ntdll.dll")]
    static extern uint NtFsControlFile(SafeFileHandle handle, IntPtr evt, IntPtr apc,
        IntPtr context, out IoStatus status, uint code, byte[] input, uint length,
        IntPtr output, uint outputLength);

    static void Put(byte[] buffer, int offset, uint value) {
        Array.Copy(BitConverter.GetBytes(value), 0, buffer, offset, 4);
    }

    public static void Activate() {
        SafeFileHandle token;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x28, out token))
            throw new Win32Exception();
        using (token) {
            Luid luid;
            if (!LookupPrivilegeValue(null, "SeLoadDriverPrivilege", out luid))
                throw new Win32Exception();
            var privilege = new Privilege { Count = 1, Luid = luid, Attributes = 2 };
            if (!AdjustTokenPrivileges(token, false, ref privilege, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception();
            int error = Marshal.GetLastWin32Error();
            if (error != 0) throw new Win32Exception(error);
        }
        using (var handle = CreateFile(@"\\?\GLOBALROOT\Device\LanmanRedirector",
            0x00100021, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception();
            byte[] name = Encoding.Unicode.GetBytes(@"\Device\vmsmb");
            // Startup ABI for the pinned Server 2025 26100.3476 test image.
            // This guest-control layout is separate from the vSMB wire protocol.
            // Configuration flags select disk/filesystem semantics, custom
            // transports, guest auth and an unsigned isolated test instance.
            byte[] request = new byte[124 + name.Length];
            Put(request, 0, 124);
            Put(request, 4, 30);
            request[12] = 0x4f;
            request[80] = 0x1f;
            Put(request, 84, 55);
            Put(request, 88, 10);
            Put(request, 92, 30);
            Put(request, 96, 30);
            request[116] = 1;
            Array.Copy(BitConverter.GetBytes((ushort)name.Length), 0, request, 118, 2);
            Array.Copy(name, 0, request, 120, name.Length);
            IoStatus io;
            uint status = NtFsControlFile(handle, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, out io, 0x001403a0, request, (uint)request.Length,
                IntPtr.Zero, 0);
            if (status != 0) throw new Exception("START_INSTANCE: 0x" + status.ToString("X8"));
        }
        using (var handle = CreateFile(@"\\?\GLOBALROOT\Device\vmsmb",
            0x00100021, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception();
            byte[] name = Encoding.Unicode.GetBytes(@"\Device\VMBus\{4d12e519-17a0-4ae4-8eaa-5270fc6abdb7}-{dcc079ae-60ba-4d07-847c-3493609c0870}-0000");
            byte[] request = new byte[16 + name.Length];
            request[0] = 16;
            Put(request, 4, 2);
            Put(request, 8, (uint)name.Length);
            Array.Copy(name, 0, request, 12, name.Length);
            IoStatus io;
            uint status = NtFsControlFile(handle, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, out io, 0x001401b0, request, (uint)request.Length,
                IntPtr.Zero, 0);
            if (status != 0) throw new Exception("BIND_TRANSPORT: 0x" + status.ToString("X8"));
        }
        if (!DefineDosDevice(1, "V:", @"\Device\vmsmb\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\memory"))
            throw new Win32Exception();
    }

    public static byte[] ReadUncached(string path, int length) {
        using (var handle = CreateFile(path, 0x80000000, 7, IntPtr.Zero, 3, 0x20000080, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception();
            IntPtr buffer = VirtualAlloc(IntPtr.Zero, new UIntPtr((uint)length), 0x3000, 4);
            if (buffer == IntPtr.Zero) throw new Win32Exception();
            try {
                uint read;
                if (!ReadFile(handle, buffer, (uint)length, out read, IntPtr.Zero))
                    throw new Win32Exception();
                if (read != length) throw new Exception("Short uncached read");
                byte[] result = new byte[length];
                Marshal.Copy(buffer, result, 0, length);
                return result;
            } finally {
                if (!VirtualFree(buffer, UIntPtr.Zero, 0x8000)) throw new Win32Exception();
            }
        }
    }
}
'@

[VsmbGuest]::Activate()
$directory = 'V:\guest-test'
[System.IO.Directory]::CreateDirectory($directory) | Out-Null
$source = Join-Path $directory 'source.bin'
$target = Join-Path $directory 'renamed.bin'
$bytes = New-Object byte[] 131077
for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $i % 251 }
[System.IO.File]::WriteAllBytes($source, $bytes)
$read = [System.IO.File]::ReadAllBytes($source)
if ($read.Length -ne $bytes.Length) { throw 'Wrong read length' }
for ($i = 0; $i -lt $read.Length; $i++) {
    if ($read[$i] -ne $bytes[$i]) { throw "Wrong byte at $i" }
}
$uncached = [VsmbGuest]::ReadUncached($source, 131072)
for ($i = 0; $i -lt $uncached.Length; $i++) {
    if ($uncached[$i] -ne $bytes[$i]) { throw "Wrong uncached byte at $i" }
}
[System.IO.File]::Move($source, $target)
$files = @([System.IO.Directory]::EnumerateFiles($directory))
if ($files.Count -ne 1) { throw 'Wrong directory contents' }
[System.IO.File]::Delete($target)
[System.IO.Directory]::Delete($directory)
Write-Output 'VSMB_FILE_OPERATIONS_PASSED'
