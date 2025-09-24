$SoftwareName = 'Remote Desktop'
[version]$TargetVersion = '1.2.6513.0'
$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.GetValue('DisplayName') -eq $SoftwareName }
$ErrorActionPreference = 'Stop'
# Perform Tests
$Installed = $False
If ([string]$registryEntry) {
    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        Write-Output "[$SoftwareName] version [$Version] is installed."
        $Installed = $True
    }
}
$Shortcut = $False
if (Test-Path -Path "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\AVD.lnk") {
    $Shortcut = $True
}
#Final Output
if ($Installed -and $Shortcut) {
    Write-Output "$SoftwareName is installed, version $version"
    Exit 0
}
Elseif ($Installed -and -not $Shortcut) {
    Write-Output "$SoftwareName is installed, but shortcut is missing"
    Exit 1
}
Elseif (-not $Installed -and $Shortcut) {
    Write-Output "$SoftwareName is not installed, but shortcut exists"
    Exit 1
}
Else {
    Write-Output "$SoftwareName is not installed, shortcut is missing"
    Exit 1
}