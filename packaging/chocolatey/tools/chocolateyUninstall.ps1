$ErrorActionPreference = 'Stop'

$packageName = 'flamberge'
$toolsDir    = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Removes the auto-generated shim and the unpacked files. Chocolatey deletes the
# package directory itself; this cleans up the zip-extracted payload + shim.
Uninstall-ChocolateyZipPackage -PackageName $packageName
Get-ChildItem -Path $toolsDir -Recurse -Filter 'flamberge.exe' |
  ForEach-Object { Uninstall-BinFile -Name 'flamberge' -Path $_.FullName }
