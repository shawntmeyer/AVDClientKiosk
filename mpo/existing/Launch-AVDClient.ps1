<# 
.SYNOPSIS
    This script launches the Remote Desktop Client for Windows, clears any cached logon information, and automatically subscribes to the Feed.
    It monitors the system for smart card removal and automatically disconnects remote sessions when this occurs. The script also monitors the Remote
    Desktop client process and closes when the process closes to remove the event subsccriber.

.DESCRIPTION 
    This script first creates a WMI Event Subscriber in this PowerShell session that looks for the removal of a PNP device that matches a
    Smart Card (PNPDeviceID always starts with SCFILTER). This subscription is configured with an action to kill all msrdc processes which
    disconnects the remote session, but does not log the user off the remote session or close the AVD Client. In order for the user to reconnect to
    any session, they must reinsert their CAC and reauthenticate. This is useful for environments where users are required to remove their CAC
    when they leave their desk.

    After the WMI Subscriber is created, the script then checks to determine if any cached user subscription is present and if it is, then the
    AVD client executable is called with the '/reset' switch to clear out this data for the new user.
    
    Next, the script launches the AVD Client with a command line that automatically starts the subscription process to populate the feed. If there
    is only one resource in the feed, then the script will automatically launch the Remote Desktop connection to this resource. Otherwise, the feed
    is displayed and the user can select the desired resource.
    
    The script monitors the MSRDCW process (Remote Deskotp Client) every 5 seconds until there is an exit code. Once there is an exit code, the script
    exits which removes the WMI Event Subscriber registration.
 
.NOTES 
    The query for the WMI Event Subscription can be adjusted to run more/less frequently on the line that begins with '$Query'. The time is an
    integer value in Seconds and found after 'WITHIN'. Default is 5 seconds.

.COMPONENT 
    No PowerShell modules required.

.LINK 
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1
    https://learn.microsoft.com/en-us/azure/virtual-desktop/uri-scheme

.Parameter SubscribeUrl
    This value determines the Url of the Remote Desktop Feed which varies by environment. The placeholder in this script is/was automatically
    updated by the installation script.
    The list of Urls can be found at
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-microsoft-store?source=recommendations#subscribe-to-a-workspace.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$SubscribeUrl
)
Start-Transcript -Path "$env:Temp\$(($MyInvocation.MyCommand.Name).Replace('.ps1', '.log'))" -Force

# Create a WMI Event Subscription
$Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.PNPDeviceID LIKE 'SCFILTER%'"
$SourceIdentifier = "Remove_SMARTCARD_Event"

Get-EventSubscriber -Force | Where-Object {$_.SourceIdentifier -eq $SourceIdentifier} | Unregister-Event -Force -ErrorAction SilentlyContinue
$EventAction = {
    $pnpEntity = $EventArgs.NewEvent.TargetInstance
    Write-Output "Device Removed:`n`tCaption: $($pnpEntity.Caption)`n`tPNPDeviceID: $($pnpEntity.PNPDeviceID)`n`tManufacturer: $($pnpEntity.Manufacturer)"
    If (Get-Process | Where-Object {$_.Name -eq 'msrdcw'}) {
        If (Get-Process | Where-Object {$_.Name -eq 'msrdc'}) {
            Write-Output "Disconnecting all open session host connections."
            Stop-Process -Name 'msrdc' -Force
            $counter = 0
            Do {
                $counter ++
                Start-Sleep -Seconds 1
            } Until ($counter -eq 30 -or (!(Get-Process | Where-Object {$_.Name -eq 'msrdc'})))
        } Else {
            Write-Output "No open session host connections."
        }
    } Else {
        Write-Output "The Remote Desktop Client is not running."
    }
}
Register-WmiEvent -Query $Query -Action $EventAction -SourceIdentifier $SourceIdentifier -SupportEvent

Function Reset-MSRDCW {
    If (Get-Process | Where-Object {$_.Name -eq 'msrdc'}) {
        Write-Output "Disconnecting all open session host connections."
        Stop-Process -Name 'msrdc' -Force
        $counter = 0
        Do {
            $counter ++
            Start-Sleep -Seconds 1
        } Until ($counter -eq 30 -or (!(Get-Process | Where-Object {$_.Name -eq 'msrdc'})))
    }
    Get-Process | Where-Object {$_.Name -eq 'msrdcw'} | Stop-Process -Force
    Get-Process | Where-Object {$_.Name -eq 'Microsoft.AAD.BrokerPlugin'} | Stop-Process -Force
    $reset = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\msrdcw.exe" -ArgumentList "/reset /f" -wait -PassThru
    Write-Output "msrdcw.exe /reset exit code: [$($reset.ExitCode)]"
}

# Handle Client Reset on launch
If (Test-Path -Path 'HKCU:\Software\Microsoft\RdClientRadc') {
    Reset-MSRDCW
}
# Turn off Telemetry on every launch since this is not a policy.
$RegKey = 'HKCU:\Software\Microsoft\RdClientRadc'
$RegValue = 'EnableMSRDCTelemetry'
New-Item -Path $RegKey -Force | Out-Null
New-ItemProperty -Path $RegKey -Name $RegValue -PropertyType DWORD -Value 0 -Force | Out-Null

Write-Output "Starting Remote Desktop Client."
If ($Null -ne $SubscribeUrl -and $SubscribeUrl -ne '') {
    $MSRDCW = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\Msrdcw.exe" -ArgumentList "ms-rd:subscribe?url=$SubscribeUrl" -PassThru
} Else {
    $MSRDCW = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\Msrdcw.exe" -PassThru
}

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
    Write-Log -EventID 505 -Message 'User Information Found. Determining if user has only 1 resource assigned to connect to that resource automatically.'
    $Apps = $AVDInfo.TenantCollection.remoteresourcecollection
    If ($SubscribeUrl -match '.us') { $env = 'usgov' } Else { $env = 'avdarm' }
    If ($apps.count -eq 1) {
        Write-Log -EventID 506 -Message 'Only 1 resource assigned to user. Automatically connecting.'
        $URL = -join ("ms-avd:connect?workspaceId=", $WorkSpaceOID, "&resourceid=", $apps.ID, "&username=", $User, "&env=", $env, "&version=0")
        Start-Process -FilePath "$URL"
    }
}

# Enter a loop that waits for the Azure Virtual Desktop client to exit. If it has not then wait for the window to exit before continuing.
Do {
    Start-Sleep -Seconds 5
} Until ($null -ne $MSRDCW.ExitCode)

Write-Output "The Remote Desktop Client closed with exit code [$($MSRDCW.exitcode)]."

If ($MSRDCW.ExitCode -ne -1) {
    # ExitCode -1 is returned when the AVD client is forceably closed with Stop-Process.
    Reset-MSRDCW  
}
Write-Output "Exiting `"$PSCommandPath`""
Stop-Transcript