$SoftwareName = 'Remote Desktop'
[version]$TargetVersion = '1.2.6676.0'
$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.GetValue('DisplayName') -eq $SoftwareName }
$ErrorActionPreference = 'Stop'
# Perform Tests
If ([string]$registryEntry) {
    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Output "[$SoftwareName] version [$Version] is installed."
    }
}