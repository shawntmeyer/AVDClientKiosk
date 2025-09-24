$TargetVersion = '2.0.704.0'

$InstalledVersion = (Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "MicrosoftCorporationII.Windows365" }).Version

If ($InstalledVersion) {
    if ($InstalledVersion -ge $TargetVersion) {
        Write-Output "Windows App version [$InstalledVersion] is installed."
        Exit 0
    }
    Else {
        Write-Output "Windows App version [$InstalledVersion] is installed, but older than target version [$TargetVersion]."
        Exit 1
    }
}
Else {
    Write-Output "Windows App is not installed."
    Exit 1
}