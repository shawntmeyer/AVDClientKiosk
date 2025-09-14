[string]$SoftwareName = 'InstallRoot'
[version]$TargetVersion = '5.6'
# Get registry entry for Citrix Workspace App
$registryEntry = Get-ChildItem Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object {$_.GetValue('DisplayName') -eq $SoftwareName}

If (([string]$registryEntry)) {

    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Host "$SoftwareName is installed"
        Write-Host "Version: $version"
        exit 0

    } else {
        Write-Host "$SoftwareName version is lower than expected. Expected: $TargetVersion, Found: $version"
        exit 1
    }
} else {
    Write-Host "$SoftwareName isn't installed"
    exit 1
}