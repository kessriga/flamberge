$ErrorActionPreference = 'Stop'

$packageName = 'flamberge'
$toolsDir    = Split-Path -Parent $MyInvocation.MyCommand.Definition
$url64       = 'https://github.com/kessriga/flamberge/releases/download/v0.1.0/flamberge-v0.1.0-x86_64-pc-windows-msvc.zip'
$checksum64  = '2521CCCADF4387B517625CB565F9556F3F37A1DA3307E4B0FA840BCC4E9329B5'

# Downloads and unpacks the release zip into the package tools directory.
# Chocolatey auto-shims the flamberge.exe it finds there onto the PATH.
Install-ChocolateyZipPackage `
  -PackageName    $packageName `
  -Url64bit       $url64 `
  -UnzipLocation  $toolsDir `
  -Checksum64     $checksum64 `
  -ChecksumType64 'sha256'
