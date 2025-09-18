$TargetVersion = '2.0.704.0'

$InstalledVersion = (Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "MicrosoftCorporationII.Windows365" }).Version

If ($InstalledVersion -and ($InstalledVersion -ge $TargetVersion)) {
    Write-Output "Windows App version [$InstalledVersion] is installed."
    Exit 0
} Else {
    Write-Output "Windows App version [$InstalledVersion] is not installed or is older than target version [$TargetVersion]."
    Exit 1
}