# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[VsmbGuest]::Activate('windows')
$directory = 'V:\guest-test'
[System.IO.Directory]::CreateDirectory($directory) | Out-Null
[VsmbGuest]::TestPausedNotification($directory)
[VsmbGuest]::TestNotifications($directory)
[VsmbGuest]::TestLocks('V:\locked.bin', $true)
if ($VsmbSoftwareCaching) {
    [VsmbGuest]::TestCaching('V:\cached.bin', $true)
}

$source = Join-Path $directory 'source.bin'
$target = Join-Path $directory 'renamed.bin'
$bytes = New-Object byte[] 131077
for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $i % 251 }
[System.IO.File]::WriteAllBytes($source, $bytes)
$read = [System.IO.File]::ReadAllBytes($source)
if ($read.Length -ne $bytes.Length) { throw 'Wrong Windows-backed read length' }
for ($i = 0; $i -lt $read.Length; $i++) {
    if ($read[$i] -ne $bytes[$i]) { throw "Wrong Windows-backed byte at $i" }
}
$uncached = [VsmbGuest]::ReadUncached($source, 131072)
for ($i = 0; $i -lt $uncached.Length; $i++) {
    if ($uncached[$i] -ne $bytes[$i]) { throw "Wrong uncached Windows-backed byte at $i" }
}
[System.IO.File]::Move($source, $target)
if ($VsmbHostChanges -and [VsmbGuest]::ReadUncached('V:\host-update.bin', 4096)[0] -ne 0x11) {
    throw 'Wrong initial Windows host data'
}
[System.IO.File]::WriteAllText('C:\vsmb-native-ready', 'ready')
while (![System.IO.File]::Exists('C:\vsmb-native-go')) {
    [System.Threading.Thread]::Sleep(10)
}
if ($VsmbHostChanges) {
    if ([VsmbGuest]::ReadUncached('V:\host-update.bin', 4096)[0] -ne 0x5a) {
        throw 'Windows host update was not visible'
    }
    [VsmbGuest]::TestHostNotification($directory)
}
[System.IO.File]::Delete($target)
[System.IO.Directory]::Delete($directory)
[System.IO.File]::WriteAllText('V:\retained.txt', 'retained')
if ($VsmbSoftwareCaching) {
    $retained = [System.IO.File]::Open('V:\retained.txt', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try { $retained.Flush($true) } finally { $retained.Dispose() }
}
Write-Output 'VSMB_WINDOWS_FILE_OPERATIONS_PASSED'
