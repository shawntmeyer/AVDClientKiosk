$SoftwareName = 'Yubikey MiniDriver'
[version]$TargetVersion = '4.6.3.252'
$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.GetValue('DisplayName') -match $SoftwareName }

If (([string]$registryEntry)) {

    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Host "$SoftwareName is installed"
        Write-Host "Version: $version"
        exit 0

    }
    else {
        Write-Host "$SoftwareName version is lower than expected. Expected: $TargetVersion, Found: $version"
        exit 1
    }
}
else {
    Write-Host "$SoftwareName isn't installed"
    exit 1
}