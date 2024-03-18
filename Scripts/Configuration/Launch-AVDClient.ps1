<# 
.SYNOPSIS
    This script launches the Remote Desktop Client for Windows and automatically subscribes to the Feed. It performs different monitoring
    actions depending on the parameters or user for who the script is running (i.e., it will create a WMI Event Subscription with actions
    if the $Autologon or $Yubikey are set to $true.). The script also monitors the Remote Desktop client for Windows process and takes actions
    when the process exits depending on exit code.

.DESCRIPTION 
    This script first creates a WMI Event Subscriber that looks for the removal of a PNP device that matches either a YUBIKEY (Vendor ID 1050)
    or a Smart Card (PNPDeviceID always starts with SCFILTER). This subscription is configured with an action to relaunch this script and kill
    the PowerShell process executing this instance if the logged in user is 'KioskUser0' because this is an autologon kiosk user and lock the
    computer if it is any other user.

    After the WMI Subscriber is created, the script then launches the AVD Client with a command line that it determines based on the signed-in
    user and whether there is cached credential information for the user in the AVD client. When launching the client, the process details are
    passed through to this script.

    The script monitors the MSRDCW process (AVD Client) every 5 seconds until there is an exit code. Once there is an exit code, the script
    either restarts this script and kills the parent PowerShell process when the signed-in user is 'KioskUser0' or logs the user off if the
    signed-in user was not 'KioskUser0' and the exit code is 0 indicating that the user clicked the 'X' button at the top right of the AVD
    Client.
 
.NOTES 
    The query for the WMI Event Subscription can be adjusted to run more/less frequently on the line that begins with '$Query'. The time is an
    integer value in Seconds and found after 'WITHIN'. Default is 5 seconds.

.COMPONENT 
    No PowerShell modules required.

.LINK 
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1
    https://learn.microsoft.com/en-us/azure/virtual-desktop/uri-scheme

.PARAMETER AutoLogon
    This boolean value determines if the Shell Launcher is configured with the Autologon account. If not, without Yubikey support, the WMI
    event subscription is not created.

.Parameter SubscribeUrl
    This value determines the Url of the Remote Desktop Feed which varies by environment. The placeholder in this script is/was automatically
    updated by the installation script.
    The list of Urls can be found at
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-microsoft-store?source=recommendations#subscribe-to-a-workspace.

.Parameter Yubikey
    This boolean value determines if the WMI Event Subscription monitors for Yubikey Removal. Default = $False
#>

[CmdletBinding()]
param (
    [Parameter()]
    [bool]$AutoLogon = $false,
    [Parameter()]
    [string]$SubscribeUrl = '<SubscribeUrl>',
    [Parameter()]
    [Bool]$Yubikey = $false
)
$VBScriptPath = $PSCommandPath.Replace('.ps1', '.vbs')
Start-Transcript -Path "$env:Temp\$(($MyInvocation.MyCommand.Name).Replace('.ps1', '.log'))" -Force

# Create a WMI Event Subscription if this is an Autologon Kiosk or Yubikey removal should trigger an action.
If ($AutoLogon -or $Yubikey) {
    If ($AutoLogon -and $Yubikey) {
        # YUBIKEY is detected as USB Device with Vendor ID = 1050
        $Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PnPEntity' AND (TargetInstance.PNPDeviceID LIKE 'USB%VID_1050%' OR TargetInstance.PNPDeviceID LIKE 'SCFILTER%')"
        $SourceIdentifier = "Remove_YUBIKEY_or_SMARTCARD_Event"
    } Elseif ($AutoLogon -and !$Yubikey) {
        $Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.PNPDeviceID LIKE 'SCFILTER%'"
        $SourceIdentifier = "Remove_SMARTCARD_Event"
    } Elseif (!$AutoLogon -and $Yubikey) {
        $Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.PNPDeviceID LIKE 'USB%VID_1050%'"
        $SourceIdentifier = "Remove_YUBIKEY_Event"
    }

    Get-EventSubscriber -Force | Where-Object {$_.SourceIdentifier -eq $SourceIdentifier} | Unregister-Event -Force -ErrorAction SilentlyContinue
    $EventAction = {
        $pnpEntity = $EventArgs.NewEvent.TargetInstance
        Write-Output "Device Removed:`n`tCaption: $($pnpEntity.Caption)`n`tPNPDeviceID: $($pnpEntity.PNPDeviceID)`n`tManufacturer: $($pnpEntity.Manufacturer)"
        If ($env:UserName -eq 'KioskUser0') {
            Write-Output "Relaunching this script."
            Stop-Transcript
            Start-Process -FilePath "wscript.exe" -ArgumentList "`"$VBScriptPath`""
            # Kill current Powershell process to prevent multiple powershell processes from running.
            Get-Process -Id $PID | Stop-Process -Force
        } Else {
            Write-Output "Locking the computer."
            Start-Process -FilePath 'rundll32.exe' -ArgumentList "user32.dll`,LockWorkStation"
        }
    }
    Register-WmiEvent -Query $Query -Action $EventAction -SourceIdentifier $SourceIdentifier -SupportEvent
}
# Handle Client Reset in the Autologon scenario
If ($Env:UserName -eq 'KioskUser0' -and (Test-Path -Path 'HKCU:\Software\Microsoft\RdClientRadc')) {
    Write-Output 'User Information Cached. Resetting the Remote Desktop Client.'
    Get-Process | Where-Object {$_.Name -eq 'msrdcw'} | Stop-Process -Force
    Get-Process | Where-Object {$_.Name -eq 'Microsoft.AAD.BrokerPlugin'} | Stop-Process -Force
    $reset = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\msrdcw.exe" -ArgumentList "/reset /f" -wait -PassThru
    Write-Output "msrdcw.exe /reset exit code: [$($reset.ExitCode)]"
}
# Turn off Telemetry on every launch since this is not a policy.
$RegKey = 'HKCU:\Software\Microsoft\RdClientRadc'
$RegValue = 'EnableMSRDCTelemetry'
New-Item -Path $RegKey -Force | Out-Null
New-ItemProperty -Path $RegKey -Name $RegValue -PropertyType DWORD -Value 0 -Force | Out-Null

Write-Output "Starting Remote Desktop Client."
If ($AutoLogon) {
    # Always start client with subscribe Url in Autologon scenario
    $MSRDCW = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\Msrdcw.exe" -ArgumentList "ms-rd:subscribe?url=$SubscribeUrl" -PassThru
} Else {
    # Start client without subscribe Url in non-Autologon scenario because GPO will handle the subscription.
    $MSRDCW = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\Msrdcw.exe" -PassThru
}

<#---Wait for this to be available on Azure US Government

$ClientDir = "$env:UserProfile\AppData\Local\rdclientwpf"
$JSONFile = Join-Path -Path $ClientDir -ChildPath 'ISubscription.json'

# Wait for JSON File to be populated or catch the case where the Remote Desktop Client window is closed.
# We have to catch ExitCode 0 as a separate condition since it evaluates as null.
do {
    If (Test-Path $JSONFile) {
        $AVDInfo = Get-Content $JSONFile | ConvertFrom-Json
        $WorkSpaceOID = $AVDInfo.TenantCollection.TenantID
        $User = $AVDInfo.Username
    }
    Start-Sleep -Seconds 1
} until ($null -ne $User -or $null -ne $MSRDCW.ExitCode)

If ($User) {
    $Apps = $AVDInfo.TenantCollection.remoteresourcecollection
    If ($SubscribeUrl -match '.us') { $env = 'avdgov' } Else { $env = 'avdarm' }
    If ($apps.count -eq 1) {
        $URL = -join("ms-avd:connect?workspaceId=", $WorkSpaceOID, "&resourceid=", $apps.ID, "&username=", $User,"&env=", $env, "&version=0")
        Start-Process -FilePath "$URL"
    }
}
--#>

# Check again to make sure the MSRDCW window has not been closed. If it has not then wait for the window to exit before continuing.
Do {
    Start-Sleep -Seconds 5
} Until ($null -ne $MSRDCW.ExitCode)

Write-Output "The Remote Desktop Client closed with exit code [$($MSRDCW.exitcode)]."

If ($Env:UserName -eq 'KioskUser0' -and $MSRDCW.ExitCode -ne -1) {
    # ExitCode -1 is returned when the AVD client is forceably closed with Stop-Process.
    Get-Process | Where-Object {$_.Name -eq 'Microsoft.AAD.BrokerPlugin'} | Stop-Process -Force
    Write-Output 'Relaunching this script.'
    Stop-Transcript
    Start-Process -FilePath "wscript.exe" -ArgumentList "`"$VBScriptPath`""
    Get-Process -Id $PID | Stop-Process -Force    
} Elseif($MSRDCW.ExitCode -eq 0) {
    # Sign out the user if they closed the Remote Desktop Client using the [X] at the top right of the window.
    Write-Output "Logging off user."
    Write-Output "Exiting `"$PSCommandPath`""
    Stop-Transcript
    Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 0
}
Write-Output "Exiting `"$PSCommandPath`""
Stop-Transcript