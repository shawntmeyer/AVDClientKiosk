[version]$TargetVersion = '25.3.10.69'
# Get registry entry for Citrix Workspace App
$registryEntry = Get-ChildItem Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object {$_.GetValue('DisplayName') -eq 'Citrix Workspace 2503'}

If (([string]$registryEntry)) {

    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Host "Citrix Workspace App is installed"
        Write-Host "Version: $version"
        exit 0

    } else {
        Write-Host "Citrix Workspace App version is lower than expected. Expected: $TargetVersion, Found: $version"
        exit 1
    }
} else {
    Write-Host "Citrix Workspace App isn't installed"
    exit 1
}