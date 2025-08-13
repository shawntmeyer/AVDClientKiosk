[version]$TargetVersion = '1.2.6424.0'
# Get registry entry for Remote Desktop client
$registryEntry = Get-ChildItem Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object {$_.GetValue('DisplayName') -eq 'Remote Desktop'}

If (([string]$registryEntry)) {

    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Host "Microsoft Remote Desktop client is installed"
        Write-Host "Version: $version"
        exit 0

    } else {
        Write-Host "Microsoft Remote Desktop client version is lower than expected. Expected: $TargetVersion, Found: $version"
        exit 1
    }
} else {
    Write-Host "Microsoft Remote Desktop client isn't installed"
    exit 1
}