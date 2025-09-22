$SoftwareName = 'Remote Desktop'
[version]$TargetVersion = '1.2.6513.0'
$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.GetValue('DisplayName') -eq $SoftwareName }
$ErrorActionPreference = 'Stop'

If ($null -ne [string]$registryEntry) {
    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        if (Test-Path -Path "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\AVD.lnk") {
            Write-Host "[$SoftwareName] version [$Version] is installed and custom desktop shortcut found."
        }
        Else {
            Throw "[$SoftwareName] version [$($Version.toString())] is installed, but the custom desktop shortcut is not found."
        }
    } Else {
        Throw "[$SoftwareName] version is lower than expected. Expected: $($TargetVersion), Found: $($version)"
    }
} Else {
    Throw "[$SoftwareName] is not installed."
}