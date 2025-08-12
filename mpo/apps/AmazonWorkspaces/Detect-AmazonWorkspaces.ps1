[version]$TargetVersion = '5.29.1.5595'
# Get registry entry for Amazon Workspaces Client
$registryEntry = Get-ChildItem Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object {$_.GetValue('DisplayName') -eq 'Amazon WorkSpaces'}

If (([string]$registryEntry)) {

    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Host "Amazon WorkSpaces Client is installed"
        Write-Host "Version: $version"
        exit 0

    } else {
        Write-Host "Amazon WorkSpaces Client version is lower than expected. Expected: $TargetVersion, Found: $version"
        exit 1
    }
} else {
    Write-Host "Amazon WorkSpaces Client isn't installed"
    exit 1
}