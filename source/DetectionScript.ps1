[CmdletBinding()]
param (
    # Version tracking for Kiosk Mode Configuration. Leave blank or remove = and everything afterwards to disable version tracking.
    [Parameter()]
    [version]
    $version = '4.6.0'
)
$RegKey = 'HKLM:\SOFTWARE\Kiosk'
$RegValue = 'Version'

If ($version -ne '' -and $null -ne $version -and (Test-Path -Path $regkey)) {
    If (Get-ItemProperty -Path $regkey -Name $RegValue -ErrorAction SilentlyContinue) {
        [version]$installedVersion = Get-ItemPropertyValue -Path $regKey -Name $RegValue
        If ($installedVersion -ge $Version) {
            Write-Output "Installed"
        }
    }
}