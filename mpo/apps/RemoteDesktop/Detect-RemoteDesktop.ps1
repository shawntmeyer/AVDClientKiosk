$SoftwareName = 'Remote Desktop'
[version]$TargetVersion = '1.2.6513.0'
$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object {$_.GetValue('DisplayName') -eq $SoftwareName}

If (([string]$registryEntry)) {

    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Host "[$SoftwareName] version [$($Version.toString())] is installed"
        exit 0

    } else {
        Write-Host "[$SoftwareName] version is lower than expected. Expected: $($TargetVersion), Found: $($version)"
        exit 1
    }
} else {
    Write-Host "[$SoftwareName] isn't installed"
    exit 1
}