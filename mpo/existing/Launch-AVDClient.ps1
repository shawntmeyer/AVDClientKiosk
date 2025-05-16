<# 
.SYNOPSIS
    This script checks for cached login information for the Remote Desktop Client for Windows in the HKCU hive. If found, it clears the cache.
    Then the script launches the Remote Desktop Client for Windows and automatically subscribes to the Feed.
    It monitors the system for smart card removal and automatically disconnects remote sessions when this occurs. The script also monitors the Remote
    Desktop client process and closes when the process closes to remove the event subsccriber.

.DESCRIPTION 
    This script first creates a WMI Event Subscriber in this PowerShell session that looks for the removal of a PNP device that matches a
    Smart Card (PNPClass = 'SmartCard'.). This subscription is configured with an action to kill all msrdc processes which
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
#region Functions
Function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $EventLog = $EventLog,
        [Parameter()]
        [string]
        $EventSource = $EventSource,
        [Parameter()]
        [string]
        [ValidateSet('Information', 'Warning', 'Error')]
        $EntryType = 'Information',
        [Parameter()]
        [Int]
        $EventID,
        [Parameter()]
        [string]
        $Message
    )
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType $EntryType -EventId $EventId -Message $Message -ErrorAction SilentlyContinue
    Switch ($EntryType) {
        'Information' { Write-Host $Message }
        'Warning' { Write-Warning $Message }
        'Error' { Write-Error $Message }
    }
}

Function Reset-MSRDCW {
    Write-Log -EventID 200 -Message "Resetting the Remote Desktop Client."
    If (Get-Process | Where-Object { $_.Name -eq 'msrdc' }) {
        Write-Log -EventID 201 -Message "Disconnecting all open session host connections."
        Stop-Process -Name 'msrdc' -Force
        $counter = 0
        Do {
            $counter ++
            Start-Sleep -Seconds 1
        } Until ($counter -eq 30 -or (!(Get-Process | Where-Object { $_.Name -eq 'msrdc' })))
    }
    Get-Process | Where-Object { $_.Name -eq 'msrdcw' } | Stop-Process -Force
    Get-Process | Where-Object { $_.Name -eq 'Microsoft.AAD.BrokerPlugin' } | Stop-Process -Force
    Write-Log -EventID 202 -Message "Removing cached credentials and configuration from the client."
    $reset = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\msrdcw.exe" -ArgumentList "/reset /f" -wait -PassThru
    Write-Log -EventID 203 -Message "msrdcw.exe /reset exit code: [$($reset.ExitCode)]"
}
#endregion Functions

#region Variables
[string]$EventLog
[string]$EventSource
$ScriptFullName = $MyInvocation.MyCommand.Path
#endregion Variables

Write-Log -EntryType Information -EventId 100 -Message "Executing '$ScriptFullName'."

# Create a WMI Event Subscription
Write-Log -EntryType Information -EventId 101 -Message "Creating a WMI Event Subscription to monitor for Smart Card removal."
$Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.PNPClass = 'SmartCard'"
$SourceIdentifier = "Remove_SMARTCARD_Event"
Get-EventSubscriber -Force | Where-Object { $_.SourceIdentifier -eq $SourceIdentifier } | Unregister-Event -Force -ErrorAction SilentlyContinue
$EventAction = {
    [string]$EventLog
    [string]$EventSource
    $pnpEntity = $EventArgs.NewEvent.TargetInstance
    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 150 -EntryType 'Information' -Message "Device Removed:`n`tCaption: $($pnpEntity.Caption)`n`tPNPDeviceID: $($pnpEntity.PNPDeviceID)`n`tManufacturer: $($pnpEntity.Manufacturer)" -ErrorAction SilentlyContinue
    If (Get-Process | Where-Object { $_.Name -eq 'msrdcw' }) {
        If (Get-Process | Where-Object { $_.Name -eq 'msrdc' }) {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 151 -EntryType 'Information' -Message "Disconnecting all open session host connections."
            Stop-Process -Name 'msrdc' -Force
            $counter = 0
            Do {
                $counter ++
                Start-Sleep -Seconds 1
            } Until ($counter -eq 30 -or (!(Get-Process | Where-Object { $_.Name -eq 'msrdc' })))
        }
        Else {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 151 -EntryType 'Information' -Message "No open session host connections." -ErrorAction SilentlyContinue
        }
    }
    Else {
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 152 -EntryType 'Information' -Message "The Remote Desktop Client is not running." -ErrorAction SilentlyContinue
    }
}
Register-WmiEvent -Query $Query -Action $EventAction -SourceIdentifier $SourceIdentifier -SupportEvent
If (Get-EventSubscriber -Force | Where-Object { $_.SourceIdentifier -eq $SourceIdentifier }) {
    Write-Log -EventID 102 -Message "WMI Event Subscription created successfully."
}
Else {
    Write-Log -EntryType Error -EventID 103 -Message "Failed to create WMI Event Subscription."
    Write-Log -EntryType Error -EventID 104 -Message "Exiting '$ScriptFullName'."
    Get-Process -Id $PID | Stop-Process -Force
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

Write-Log -EventID 110 -Message "Starting Remote Desktop Client."
If ($Null -ne $SubscribeUrl -and $SubscribeUrl -ne '') {
    $MSRDCW = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\Msrdcw.exe" -ArgumentList "ms-rd:subscribe?url=$SubscribeUrl" -PassThru
}
Else {
    $MSRDCW = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\Msrdcw.exe" -PassThru
}

$ClientDir = "$env:UserProfile\AppData\Local\rdclientwpf"
$JSONFile = Join-Path -Path $ClientDir -ChildPath 'ISubscription.json'

# Wait for JSON File to be populated or catch the case where the Remote Desktop Client window is closed.
# We have to catch ExitCode 0 as a separate condition since it evaluates as null.
Write-Log -EventId 111 -Message "Waiting for the Remote Desktop Client to populate the JSON file to get feed information."
do {
    If (Test-Path $JSONFile) {
        $AVDInfo = Get-Content $JSONFile | ConvertFrom-Json
        $WorkSpaceOID = $AVDInfo.TenantCollection.TenantID
        $User = $AVDInfo.Username
    }
    Start-Sleep -Seconds 1
} until ($null -ne $User -or $null -ne $MSRDCW.ExitCode)

If ($User) {
    Write-Log -EventId 112 -Message "'$User' feed downloaded. Determining if user has only 1 resource assigned to connect to that resource automatically."
    $Apps = $AVDInfo.TenantCollection.remoteresourcecollection
    If ($SubscribeUrl -match '.us') { $env = 'usgov' } Else { $env = 'avdarm' }
    If ($apps.count -eq 1) {
        Write-Log -EventId 113 -Message 'Only 1 resource assigned to user. Automatically connecting to the resource.'
        $URL = -join ("ms-avd:connect?workspaceId=", $WorkSpaceOID, "&resourceid=", $apps.ID, "&username=", $User, "&env=", $env, "&version=0")
        Start-Process -FilePath "$URL"
    }
    Else {
        Write-Log -EventID 114 -Message 'User has either 0 or more than 1 resource assigned. Not taking action.'
    }
}

# Enter a loop that waits for the Azure Virtual Desktop client to exit. If it has not then wait for the window to exit before continuing.
Write-Log -EventID 115 -Message "Waiting for the Remote Desktop Client to exit or the smart card to be removed."
Do {
    Start-Sleep -Seconds 5
} Until ($null -ne $MSRDCW.ExitCode)

Write-Log -EventID 198 -Message "The Remote Desktop Client closed with exit code [$($MSRDCW.exitcode)]."

If ($MSRDCW.ExitCode -ne -1) {
    # ExitCode -1 is returned when the AVD client is forceably closed with Stop-Process.
    Reset-MSRDCW  
}
Write-Log -EventID 199 -Message "Exiting `"$ScriptFullName`""
