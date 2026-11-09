# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
foreach ($signal in @('C:\vsmb-resume', 'C:\vsmb-lock-go', 'C:\vsmb-cache-go', 'C:\vsmb-cache-read-go', 'C:\vsmb-idle-go')) {
    [System.IO.File]::Delete($signal)
}

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
    [StructLayout(LayoutKind.Sequential)]
    struct UnicodeString {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ObjectAttributes {
        public uint Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Overlapped {
        public UIntPtr Internal, InternalHigh;
        public uint Offset, OffsetHigh;
        public IntPtr Event;
    }

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
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern SafeWaitHandle CreateEvent(IntPtr attributes, bool manualReset, bool initialState, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(SafeWaitHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetOverlappedResult(SafeFileHandle handle, IntPtr overlapped, out uint bytes, bool wait);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CancelIoEx(SafeFileHandle handle, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool LockFileEx(SafeFileHandle handle, uint flags, uint reserved, uint low, uint high, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UnlockFileEx(SafeFileHandle handle, uint reserved, uint low, uint high, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadDirectoryChangesW(SafeFileHandle handle, IntPtr buffer, uint length,
        bool subtree, uint filter, IntPtr returned, IntPtr overlapped, IntPtr completion);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFilePointerEx(SafeFileHandle handle, long distance, out long position, uint method);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateHardLink(string name, string existing, IntPtr security);
    [DllImport("ntdll.dll")]
    static extern uint NtFsControlFile(SafeFileHandle handle, IntPtr evt, IntPtr apc,
        IntPtr context, out IoStatus status, uint code, byte[] input, uint length,
        IntPtr output, uint outputLength);
    [DllImport("ntdll.dll")]
    static extern uint NtCreateFile(out SafeFileHandle handle, uint access,
        ref ObjectAttributes attributes, out IoStatus status, IntPtr allocationSize,
        uint fileAttributes, uint share, uint disposition, uint options,
        IntPtr eaBuffer, uint eaLength);

    static void Put(byte[] buffer, int offset, uint value) {
        Array.Copy(BitConverter.GetBytes(value), 0, buffer, offset, 4);
    }

    public static void Activate() { Activate("memory"); }

    public static void Activate(string shareName) {
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
        string share = @"\Device\vmsmb\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\" + shareName;
        MountShare(share);
        if (!DefineDosDevice(1, "V:", share))
            throw new Win32Exception();
    }

    static void MountShare(string path) {
        IntPtr buffer = Marshal.StringToHGlobalUni(path);
        IntPtr name = IntPtr.Zero;
        try {
            var unicode = new UnicodeString {
                Length = checked((ushort)(path.Length * 2)),
                MaximumLength = checked((ushort)((path.Length + 1) * 2)),
                Buffer = buffer
            };
            name = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
            Marshal.StructureToPtr(unicode, name, false);
            var attributes = new ObjectAttributes {
                Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)),
                ObjectName = name,
                Attributes = 0x40
            };
            SafeFileHandle handle;
            IoStatus io;
            const uint TreeConnectAttributePinned = 2;
            const uint FileCreateTreeConnection = 0x80;
            const uint FileSynchronousIoNonalert = 0x20;
            // Pin the tree connection independently of application file handles.
            uint status = NtCreateFile(out handle, 0x00100080, ref attributes,
                out io, IntPtr.Zero, TreeConnectAttributePinned, 7, 1,
                FileCreateTreeConnection | FileSynchronousIoNonalert, IntPtr.Zero, 0);
            using (handle) {
                if (status != 0)
                    throw new Exception("MOUNT_SHARE: 0x" + status.ToString("X8"));
            }
        } finally {
            if (name != IntPtr.Zero) Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(buffer);
        }
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

        sealed class Pending : IDisposable {
            public readonly IntPtr Ov, Buffer;
            readonly SafeFileHandle file;
            readonly SafeWaitHandle evt;
            bool active;

            public Pending(SafeFileHandle file, uint offset) {
                this.file = file;
                evt = CreateEvent(IntPtr.Zero, true, false, null);
                if (evt.IsInvalid) throw new Win32Exception();
                Ov = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Overlapped)));
                Buffer = Marshal.AllocHGlobal(4096);
                Marshal.StructureToPtr(new Overlapped {
                    Offset = offset, Event = evt.DangerousGetHandle()
                }, Ov, false);
            }

            public void Lock(uint flags, bool mustPend, int expectedError = 0) {
                bool result = LockFileEx(file, flags, 0, 16, 0, Ov);
                int error = result ? 0 : Marshal.GetLastWin32Error();
                active = !result;
                if (error != 997) {
                    active = false;
                    if (error != expectedError)
                        throw new Exception("Lock error " + error + ", expected " + expectedError);
                }
                if (mustPend && !active) throw new Exception("Conflicting lock did not pend");
                if (!mustPend && active) Complete(expectedError);
            }

            public void Notify() {
                if (!ReadDirectoryChangesW(file, Buffer, 4096, false, 1,
                    IntPtr.Zero, Ov, IntPtr.Zero)) throw new Win32Exception();
                active = true;
                uint bytes;
                if (GetOverlappedResult(file, Ov, out bytes, false))
                    throw new Exception("Watch completed without a change");
                int error = Marshal.GetLastWin32Error();
                if (error != 996) throw new Win32Exception(error);
            }

            public void Cancel() {
                if (!CancelIoEx(file, Ov)) throw new Win32Exception();
            }

            public void ClosePending() {
                file.Dispose();
                if (WaitForSingleObject(evt, 5000) != 0)
                    Environment.FailFast("Closing handle did not drain its notification");
                active = false;
                uint status = unchecked((uint)Marshal.ReadIntPtr(Ov).ToInt64());
                if (status != 0xc0000120 && status != 0x10b)
                    throw new Exception("Unexpected close notification status: 0x" + status.ToString("X8"));
            }

            public uint Complete(int expectedError) {
                if (WaitForSingleObject(evt, 5000) != 0) {
                    CancelIoEx(file, Ov);
                    if (WaitForSingleObject(evt, 5000) != 0)
                        Environment.FailFast("vSMB operation failed to drain after timeout");
                    active = false;
                    throw new TimeoutException("vSMB pending operation timed out");
                }
                uint bytes;
                bool result = GetOverlappedResult(file, Ov, out bytes, false);
                int error = result ? 0 : Marshal.GetLastWin32Error();
                active = false;
                if (error != expectedError)
                    throw new Exception("Completion error " + error + ", expected " + expectedError);
                return bytes;
            }

            public void Unlock() {
                if (!UnlockFileEx(file, 0, 16, 0, Ov)) throw new Win32Exception();
            }

            public void Dispose() {
                if (active) {
                    CancelIoEx(file, Ov);
                    if (WaitForSingleObject(evt, 5000) != 0)
                        Environment.FailFast("vSMB operation still owns its buffers");
                }
                Marshal.FreeHGlobal(Buffer);
                Marshal.FreeHGlobal(Ov);
                evt.Dispose();
            }
        }

        static SafeFileHandle OpenAsync(string path, bool directory) {
            var file = CreateFile(path, directory ? 1u : 0xc0000000u, 7,
                IntPtr.Zero, 3, directory ? 0x42000000u : 0x40000080u, IntPtr.Zero);
            if (file.IsInvalid) throw new Win32Exception();
            return file;
        }

        public static void TestLocks(string path) { TestLocks(path, false); }

        public static void TestLocks(string path, bool prelinked) {
            System.IO.File.WriteAllBytes(path, new byte[4096]);
            string alias = path + ".alias";
            if (!prelinked && !CreateHardLink(alias, path, IntPtr.Zero)) throw new Win32Exception();
            using (var first = OpenAsync(path, false))
            using (var second = OpenAsync(alias, false)) {
                Console.WriteLine("VSMB_SHARED_LOCKS");
                using (var shared1 = new Pending(first, 64))
                using (var shared2 = new Pending(second, 64)) {
                    shared1.Lock(0, false);
                    shared2.Lock(0, false);
                    shared2.Unlock();
                    shared1.Unlock();
                }
                using (var owner = new Pending(first, 64)) {
                    Console.WriteLine("VSMB_EXCLUSIVE_LOCKS");
                    owner.Lock(2, false);
                    using (var conflict = new Pending(second, 64)) {
                        conflict.Lock(3, false, 33);
                    }
                    using (var cancelled = new Pending(second, 64)) {
                        cancelled.Lock(2, true);
                        cancelled.Cancel();
                        cancelled.Complete(995);
                    }
                    using (var waiter = new Pending(second, 64)) {
                        Console.WriteLine("VSMB_UNLOCK_WAITER");
                        waiter.Lock(2, true);
                        System.IO.File.WriteAllText(@"C:\vsmb-lock-ready", "ready");
                        var deadline = Stopwatch.StartNew();
                        while (!System.IO.File.Exists(@"C:\vsmb-lock-go")) {
                            if (deadline.ElapsedMilliseconds > 20000)
                                throw new TimeoutException("Host did not inspect pending lock");
                            System.Threading.Thread.Sleep(10);
                        }
                        owner.Unlock();
                        waiter.Complete(0);
                        waiter.Unlock();
                    }
                    owner.Lock(2, false);
                    using (var waiter = new Pending(second, 64)) {
                        Console.WriteLine("VSMB_CLOSE_WAITER");
                        waiter.Lock(2, true);
                        first.Dispose();
                        waiter.Complete(0);
                        waiter.Unlock();
                    }
                }
            }
            System.IO.File.Delete(alias);
            System.IO.File.Delete(path);
        }

        public static void TestHostNotification(string directory) {
            using (var handle = OpenAsync(directory, true))
            using (var watch = new Pending(handle, 0)) {
                watch.Notify();
                System.IO.File.WriteAllText(@"C:\vsmb-native-watch-ready", "ready");
                uint bytes = watch.Complete(0);
                int length = Marshal.ReadInt32(watch.Buffer, 8);
                if (bytes < 12 || Marshal.ReadInt32(watch.Buffer, 4) != 1 ||
                    Marshal.PtrToStringUni(IntPtr.Add(watch.Buffer, 12), length / 2) != "from-host.bin")
                    throw new Exception("Wrong host directory notification");
                System.IO.File.Delete(System.IO.Path.Combine(directory, "from-host.bin"));
            }
        }

        public static void TestNotifications(string directory) {
            using (var closing = OpenAsync(directory, true))
            using (var watch = new Pending(closing, 0)) {
                watch.Notify();
                watch.ClosePending();
            }
            using (var handle = OpenAsync(directory, true)) {
                using (var cancelled = new Pending(handle, 0)) {
                    cancelled.Notify();
                    cancelled.Cancel();
                    cancelled.Complete(995);
                }
                using (var watch = new Pending(handle, 0)) {
                    watch.Notify();
                    string path = System.IO.Path.Combine(directory, "notified.bin");
                    System.IO.File.WriteAllBytes(path, new byte[1]);
                    uint bytes = watch.Complete(0);
                    int length = Marshal.ReadInt32(watch.Buffer, 8);
                    if (bytes < 12 || Marshal.ReadInt32(watch.Buffer, 4) != 1 ||
                        length != "notified.bin".Length * 2 ||
                        Marshal.PtrToStringUni(IntPtr.Add(watch.Buffer, 12), length / 2) != "notified.bin")
                        throw new Exception("Wrong directory notification");
                    System.IO.File.Delete(path);
                }
            }

        }

            public static void TestPausedNotification(string directory) {
                using (var handle = OpenAsync(directory, true))
                using (var watch = new Pending(handle, 0)) {
                    watch.Notify();
                    var deadline = Stopwatch.StartNew();
                    while (!System.IO.File.Exists(@"C:\vsmb-resume")) {
                        if (deadline.ElapsedMilliseconds > 20000)
                            throw new TimeoutException("Host did not resume notification test");
                        System.Threading.Thread.Sleep(10);
                    }
                    string path = System.IO.Path.Combine(directory, "resumed.bin");
                    System.IO.File.WriteAllBytes(path, new byte[1]);
                    watch.Complete(0);
                    System.IO.File.Delete(path);
                }
            }

            public static void TestCaching(string path) {
                System.IO.File.WriteAllBytes(path, new byte[4096]);
                string alias = path + ".alias";
                if (!CreateHardLink(alias, path, IntPtr.Zero)) throw new Win32Exception();
                using (var first = CreateFile(path, 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
                    if (first.IsInvalid) throw new Win32Exception();
                    using (var buffer = new Pending(first, 0)) {
                    uint read;
                    if (!ReadFile(first, buffer.Buffer, 4096, out read, IntPtr.Zero))
                        throw new Win32Exception();
                    if (read != 4096 || Marshal.ReadByte(buffer.Buffer) != 0)
                        throw new Exception("Wrong initial cached data");
                    System.IO.File.WriteAllText(@"C:\vsmb-cache-ready", "ready");
                    var deadline = Stopwatch.StartNew();
                    while (!System.IO.File.Exists(@"C:\vsmb-cache-go")) {
                        if (deadline.ElapsedMilliseconds > 20000)
                            throw new TimeoutException("Host did not inspect caching grant");
                        System.Threading.Thread.Sleep(10);
                    }
                    using (var stream = new System.IO.FileStream(alias,
                        System.IO.FileMode.Open, System.IO.FileAccess.Write,
                        System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete)) {
                        stream.WriteByte(0x5a);
                        stream.Flush(true);
                    }
                    System.IO.File.WriteAllText(@"C:\vsmb-cache-ready", "written");
                    deadline.Restart();
                    while (!System.IO.File.Exists(@"C:\vsmb-cache-read-go")) {
                        if (deadline.ElapsedMilliseconds > 20000)
                            throw new TimeoutException("Host did not inspect caching break");
                        System.Threading.Thread.Sleep(10);
                    }
                    long position;
                    if (!SetFilePointerEx(first, 0, out position, 0) ||
                        !ReadFile(first, buffer.Buffer, 4096, out read, IntPtr.Zero))
                        throw new Win32Exception();
                    if (read != 4096 || Marshal.ReadByte(buffer.Buffer) != 0x5a)
                        throw new Exception("Stale cached data after alias write");
                    }
                }
                if (ReadUncached(path, 4096)[0] != 0x5a)
                    throw new Exception("Stale data after caching break");
                System.IO.File.Delete(alias);
                System.IO.File.Delete(path);
            }
}
'@

[VsmbGuest]::Activate()
$directory = 'V:\guest-test'
[System.IO.Directory]::CreateDirectory($directory) | Out-Null
[VsmbGuest]::TestPausedNotification($directory)
[VsmbGuest]::TestNotifications($directory)
[VsmbGuest]::TestLocks((Join-Path $directory 'locked.bin'))
[VsmbGuest]::TestCaching((Join-Path $directory 'cached.bin'))
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
[System.IO.File]::WriteAllBytes('V:\idle.bin', [byte[]](1, 2, 3))
[System.IO.File]::WriteAllText('C:\vsmb-idle-ready', 'ready')
while (![System.IO.File]::Exists('C:\vsmb-idle-go')) {
    [System.Threading.Thread]::Sleep(25)
}
$idle = [System.IO.File]::ReadAllBytes('V:\idle.bin')
if ($idle.Length -ne 3 -or $idle[0] -ne 1 -or $idle[1] -ne 2 -or $idle[2] -ne 3) {
    throw 'Wrong file contents after idle'
}
[System.IO.File]::Delete('V:\idle.bin')
Write-Output 'VSMB_FILE_OPERATIONS_PASSED'
