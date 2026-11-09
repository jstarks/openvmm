# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[VsmbGuest]::Activate('linux')
$directory = 'V:\guest-test'
[System.IO.Directory]::CreateDirectory($directory) | Out-Null
[VsmbGuest]::TestPausedNotification($directory)
[VsmbGuest]::TestNotifications($directory)
[VsmbGuest]::TestLocks('V:\locked.bin', $true)

$source = Join-Path $directory 'source.bin'
$target = Join-Path $directory 'renamed.bin'
$bytes = New-Object byte[] 131077
for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $i % 251 }
[System.IO.File]::WriteAllBytes($source, $bytes)
$read = [System.IO.File]::ReadAllBytes($source)
if ($read.Length -ne $bytes.Length) { throw 'Wrong native read length' }
for ($i = 0; $i -lt $read.Length; $i++) {
    if ($read[$i] -ne $bytes[$i]) { throw "Wrong native byte at $i" }
}
$uncached = [VsmbGuest]::ReadUncached($source, 131072)
for ($i = 0; $i -lt $uncached.Length; $i++) {
    if ($uncached[$i] -ne $bytes[$i]) { throw "Wrong uncached native byte at $i" }
}
[System.IO.File]::Move($source, $target)
$mapped = 'V:\colon' + [char]0xf03a + 'name'
if ([System.IO.File]::ReadAllText($mapped) -ne 'projected') { throw 'Wrong filename projection' }
if ([VsmbGuest]::ReadUncached('V:\host-update.bin', 4096)[0] -ne 0x11) {
    throw 'Wrong initial host data'
}
[System.IO.File]::WriteAllText('C:\vsmb-native-ready', 'ready')
while (![System.IO.File]::Exists('C:\vsmb-native-go')) {
    [System.Threading.Thread]::Sleep(10)
}
if ([VsmbGuest]::ReadUncached('V:\host-update.bin', 4096)[0] -ne 0x5a) {
    throw 'Host update was not visible'
}
[VsmbGuest]::TestHostNotification($directory)
[System.IO.File]::Delete($target)
[System.IO.Directory]::Delete($directory)
[System.IO.File]::WriteAllText('V:\retained.txt', 'retained')
Write-Output 'VSMB_LINUX_FILE_OPERATIONS_PASSED'
