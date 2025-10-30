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

.PARAMETER DeviceVendorID
    This string value is the Vendor ID of the device to monitor for removal. The default is an empty string.

.PARAMETER SmartCard
    This boolean value determines if the WMI Event Subscription monitors for Smart Card Removal. Default = $True

.PARAMETER SubscribeUrl
    This value determines the Url of the Remote Desktop Feed which varies by environment. The placeholder in this script is/was automatically
    updated by the installation script.
    The list of Urls can be found at
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-microsoft-store?source=recommendations#subscribe-to-a-workspace.

.PARAMETER Timeout
    This integer value determines the time in seconds that can pass with cached credentials in the Remote Desktop Client and no remote sessions connections. Default = 900 seconds.

.PARAMETER Triggers
    This array value determines the triggers for the actions that this script will take. The choices are ( 'SessionDisconnect', 'SessionDisconnect' and 'IdleTimeout' or 'IdleTimeout' )  or 'DeviceRemoval'.

.PARAMETER TriggerAction
    The action this script executes when the Trigger occurs. The choices are 'Lock', 'Logoff', 'ResetClient'.

#>

[CmdletBinding()]
param (
    [string]$SubscribeUrl,

    [string]$DeviceRemovalAction,

    [string]$DeviceVendorID,

    [bool]$SmartCard,

    [string]$IdleTimeoutAction,

    [int]$IdleTimeout,

    [string]$SystemDisconnectAction,

    [string]$UserDisconnectSignOutAction
)

$VBScriptPath = $PSCommandPath.Replace('.ps1', '.vbs')
[string]$EventLog
[string]$EventSource

Function Restart-Script {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 550 -Message "Relaunching $($MyInvocation.MyCommand.Name) after killing all processes." -ErrorAction Silently
    $ProcessList = 'Microsoft.AAD.BrokerPlugin', 'msrdc', 'msrdcw'
    $Processes = Get-Process
    ForEach ($Process in $ProcessList) {
        $Processes | Where-Object { $_.Name -eq $Process } | Stop-Process -Force
    }
    Start-Process -FilePath "wscript.exe" -ArgumentList "`"$VBScriptPath`""
    # Kill current Powershell process to prevent multiple powershell processes from running.
    Get-Process -Id $PID | Stop-Process -Force
}

Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 500 -Message "Starting $($MyInvocation.MyCommand.Name)" -ErrorAction SilentlyContinue

# Handle Client Reset in the Autologon scenario
If ($Env:UserName -eq 'KioskUser0' -and (Test-Path -Path 'HKCU:\Software\Microsoft\RdClientRadc\Feeds')) {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 501 -Message "User Information Cached. Resetting the Remote Desktop Client."
    Get-Process | Where-Object { $_.Name -eq 'msrdcw' } | Stop-Process -Force
    Get-Process | Where-Object { $_.Name -eq 'Microsoft.AAD.BrokerPlugin' } | Stop-Process -Force
    $reset = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\msrdcw.exe" -ArgumentList "/reset /f" -wait -PassThru
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 502 -Message "msrdcw.exe /reset exit code: [$($reset.ExitCode)]" -ErrorAction SilentlyContinue
}
# Turn off Telemetry on every launch since this is not a policy.
$RegKey = 'HKCU:\Software\Microsoft\RdClientRadc'
$RegValue = 'EnableMSRDCTelemetry'
New-Item -Path $RegKey -Force | Out-Null
New-ItemProperty -Path $RegKey -Name $RegValue -PropertyType DWORD -Value 0 -Force | Out-Null
Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 503 -Message "Starting the Remote Desktop Client." -ErrorAction SilentlyContinue

If ($Env:UserName -eq 'KioskUser0') {
    # Always start client with subscribe Url in Autologon scenario
    $MSRDCW = Start-Process -FilePath "ms-rd:subscribe?url=$SubscribeUrl" -PassThru -WindowStyle Maximized
}
Else {
    # Start client without subscribe Url in non-Autologon scenario because GPO will handle the subscription.
    $MSRDCW = Start-Process -FilePath "ms-rd:" -PassThru -WindowStyle Maximized
}

If ($SubscribeUrl -match '.us' -or $SubscribeUrl -match '.com') {
    $ClientDir = "$env:UserProfile\AppData\Local\rdclientwpf"
    $JSONFile = Join-Path -Path $ClientDir -ChildPath 'ISubscription.json'

    # Wait for JSON File to be populated or catch the case where the Remote Desktop Client window is closed.
    # We have to catch ExitCode 0 as a separate condition since it evaluates as null.
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 504 -Message "Waiting for feed download." -ErrorAction SilentlyContinue
    do {
        If (Test-Path $JSONFile) {
            $AVDInfo = Get-Content $JSONFile | ConvertFrom-Json
            $WorkSpaceOID = $AVDInfo.TenantCollection.TenantID
            $User = $AVDInfo.Username
        }
        Start-Sleep -Seconds 1
    } until ($null -ne $User -or $null -ne $MSRDCW.ExitCode)

    If ($User) {
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 505 -Message "User: $($User) feed downloaded. Determining if only 1 resource is published." -ErrorAction SilentlyContinue
        $Apps = $AVDInfo.TenantCollection.remoteresourcecollection
        If ($SubscribeUrl -match '.us') { $env = 'usgov' } Else { $env = 'avdarm' }
        If ($apps.count -eq 1) {
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 506 -Message "Only 1 resource assigned to user. Automatically connecting." -ErrorAction SilentlyContinue
            $URL = -join ("ms-avd:connect?workspaceId=", $WorkSpaceOID, "&resourceid=", $apps.ID, "&username=", $User, "&env=", $env, "&version=0")
            Start-Process -FilePath "$URL"
        }
    }
}

# DeviceRemovalAction
If ($DeviceRemovalAction) {
    If ($DeviceVendorID) {
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 510 -Message "Creating WMI Event Subscription to detect the removal of Devices from Vendor ID: $DeviceVendorId." -ErrorAction SilentlyContinue
        $InstanceDevicePropsQuery = "TargetInstance.PNPDeviceID LIKE '%VID_$DeviceVendorID%'"
    }
    Else {
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 510 -Message "Creating WMI Event Subscription to detect the removal of Smart Cards." -ErrorAction SilentlyContinue
        $InstanceDevicePropsQuery = "TargetInstance.PNPClass = 'SmartCard'"
    }            
    $Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PnPEntity' AND ($InstanceDevicePropsQuery)"
    $SourceIdentifier = "Remove_Security_Device_Event"
    Get-EventSubscriber -Force | Where-Object { $_.SourceIdentifier -eq $SourceIdentifier } | Unregister-Event -Force -ErrorAction SilentlyContinue
    If ($DeviceRemovalAction -eq 'ResetClient') {
        $Action = {
            [CmdletBinding()]
            param (
                [string]$EventLog,
                [string]$EventSource
            )

            Function Restart-Script {
                Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 550 -Message "Relaunching $($MyInvocation.MyCommand.Name) after killing all processes." -ErrorAction SilentlyContinue
                $ProcessList = 'Microsoft.AAD.BrokerPlugin', 'msrdc', 'msrdcw'
                $Processes = Get-Process
                ForEach ($Process in $ProcessList) {
                    $Processes | Where-Object { $_.Name -eq $Process } | Stop-Process -Force
                }
                Start-Process -FilePath "wscript.exe" -ArgumentList "`"$VBScriptPath`""
                # Kill current Powershell process to prevent multiple powershell processes from running.
                Get-Process -Id $PID | Stop-Process -Force
            }
            
            If (Test-Path -Path 'HKCU:\Software\Microsoft\RdClientRadc\Feeds') { $CachePresent = $true }
            If (Get-Process | Where-Object { $_.Name -eq 'msrdcw' }) { $MSRDCWOpen = $true }
            $pnpEntity = $EventArgs.NewEvent.TargetInstance
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 525 -Message "Device Removed:`n`tCaption: $($pnpEntity.Caption)`n`tPNPDeviceID: $($pnpEntity.PNPDeviceID)`n`tManufacturer: $($pnpEntity.Manufacturer)" -ErrorAction SilentlyContinue
            If ($MSRDCWOpen -and -not $CachePresent) {
                Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 526 -Message "The MSRDCW window is open and there are no cached credentials. Nothing to do." -ErrorAction SilentlyContinue
            }
            Else {
                Restart-Script
            }
        }
    }
    ElseIf ($DeviceRemovalAction -eq 'Lock') {
        $Action = {
            [CmdletBinding()]
            param (
                [string]$EventLog,
                [string]$EventSource
            )
            $pnpEntity = $EventArgs.NewEvent.TargetInstance
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 525 -Message "Device Removed:`n`tCaption: $($pnpEntity.Caption)`n`tPNPDeviceID: $($pnpEntity.PNPDeviceID)`n`tManufacturer: $($pnpEntity.Manufacturer)" -ErrorAction SilentlyContinue
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 526 -Message "Locking the computer." -ErrorAction SilentlyContinue                  
            Start-Process -FilePath 'rundll32.exe' -ArgumentList "user32.dll`,LockWorkStation"
        }
    }
    Else {
        $Action = {
            [CmdletBinding()]
            param (
                [string]$EventLog,
                [string]$EventSource
            )
            $pnpEntity = $EventArgs.NewEvent.TargetInstance
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 525 -Message "Device Removed:`n`tCaption: $($pnpEntity.Caption)`n`tPNPDeviceID: $($pnpEntity.PNPDeviceID)`n`tManufacturer: $($pnpEntity.Manufacturer)" -ErrorAction SilentlyContinue
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 526 -Message "Logging off the user." -ErrorAction SilentlyContinue
            Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 0
        }
    }
    Register-CimIndicationEvent -Query $Query -Action $Action -SourceIdentifier $SourceIdentifier -SupportEvent
}

If ($SessionDisconnectAction -or $UserDisconnectSignOutAction) {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 510 -Message "Creating WMI Event Subscription for Remote Session Disconnect." -ErrorAction SilentlyContinue
    $Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.Logfile = 'Microsoft-Windows-TerminalServices-RDPClient/Operational' AND TargetInstance.EventCode = '1026'"
    $SourceIdentifier = "Session_Disconnect_Event"
    Get-EventSubscriber -Force | Where-Object { $_.SourceIdentifier -eq $SourceIdentifier } | Unregister-Event -Force -ErrorAction SilentlyContinue
    $Action = {
        [CmdletBinding()]
        param (
            [string]$EventLog,
            [string]$EventSource,
            [string]$SystemDisconnectAction,
            [string]$UserDisconnectSignOutAction
        )

        Function Restart-Script {
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 550 -Message "Relaunching $($MyInvocation.MyCommand.Name) after killing all processes." -ErrorAction SilentlyContinue
            $ProcessList = 'Microsoft.AAD.BrokerPlugin', 'msrdc', 'msrdcw'
            $Processes = Get-Process
            ForEach ($Process in $ProcessList) {
                $Processes | Where-Object { $_.Name -eq $Process } | Stop-Process -Force
            }                
            Start-Process -FilePath "wscript.exe" -ArgumentList "`"$VBScriptPath`""
            # Kill current Powershell process to prevent multiple powershell processes from running.
            Get-Process -Id $PID | Stop-Process -Force
        }

        Function Get-MSRDCProcess {
            If (Get-Process | Where-Object { $_.Name -eq 'msrdc' }) {
                $counter = 0
                Write-EventLog -LogName $EventLog -EventSource $EventSource -EntryType 'Information' -EventID 579 -Message 'Detected open MSRDC connections. Waiting up to 30 seconds for them to disconnect.' -ErrorAction SilentlyContinue
                Do {
                    $counter ++
                    Start-Sleep -Seconds 1
                } Until ($counter -eq 30 -or ($null -eq (Get-Process | Where-Object { $_.Name -eq 'msrdc' })))
                If ($Counter -lt 30) {
                    Write-EventLog -LogName $EventLog -EventSource $EventSource -EntryType 'Information' -EventID 580 -Message "Open connections closed after $counter seconds." -ErrorAction SilentlyContinue
                    Return $false
                }
            }
            Else {
                Return $false
            }
            Return $true
        }

        If (Test-Path -Path 'HKCU:\Software\Microsoft\RdClientRadc\Feeds') { $CachePresent = $true }
        If (Get-Process | Where-Object { $_.Name -eq 'msrdcw' }) { $MSRDCWOpen = $true }

        If ($Env:UserName -eq 'KioskUser0' -and $MSRDCWOpen -and -not $CachePresent) {
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 530 -Message "The MSRDCW window is open and there are no cached credentials. Nothing to do." -ErrorAction SilentlyContinue
        }
        Else {
            If (-Not $MSRDCWOpen) {
                Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 531 -Message "MSRDCW is not running. Assuming that the user closed the client window." -ErrorAction SilentlyContinue
                If ($Env:UserName -eq 'KioskUser0') {
                    Restart-Script
                }
                Else {
                    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 527 -Message "Logging off user." -ErrorAction SilentlyContinue
                    Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 0
                }                
            }
            # This is main section where we look at session host disconnect events in the event log and determine if we need to take action.
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 575 -Message "Filtering Session Disconnect (EventId: 1026) messages in the 'Microsoft-Windows-TerminalServices-RDPClient/Operational' log." -ErrorAction SilentlyContinue

            # Initial event filter
            $TwoMinsAgo = (Get-Date).AddMinutes(-2)
            $EventFilter = @{
                LogName   = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
                Id        = '1026'
                StartTime = $TwoMinsAgo
            }
            $Events = Get-WinEvent -FilterHashtable $EventFilter
            <#
                There are three reasons that we need to reset the client in the autologon scenario.
                Reason 1 (User Initiatiated):
                Occurs when X is select on the RDP window.

                Reason 2 (User Initiated)
                Occurs when disconnect is selected in start menu on Session Host
                Occurs when logoff is select in session

                Reason 3 (System Initiated):
                Occurs when timeout is reached on remote host or lock is selected on remote host.
            #>
            # Find the interesting events
            $MessageFilter = { $_.message -like '*(Reason= 1)' -or $_.message -like '*(Reason= 2)' }
            $UserInitiatedEvents = $Events | where-object $MessageFilter
            $MessageFilter = { $_.message -like '*(Reason= 3)' }
            $SystemInitiatedEvents = $Events | Where-Object $MessageFilter
            [int]$TotalFilteredEvents = $UserInitiatedEvents.Count + $SystemInitiatedEvents.Count
            Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventID 576 -Message "Event Log Filtering Results:`n`nTotal unfiltered 1026 events: $($Events.count) ; Total filtered by reason code: $TotalFilteredEvents" -ErrorAction SilentlyContinue

            # Must consider system initiated events first because they tell us that the user may not be present at the local terminal and we want to take actions immediately
            If ($SystemInitiatedEvents) {
                Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 577 -Message "A RDP connection was disconnected by the system either due to a timeout on the session host (SSO configuration), user locking the remote session, or a connection to the same host pool from a different client." -ErrorAction SilentlyContinue

                If (Get-MSRDCProcess -eq $false) {
                    If ($SystemDisconnectAction -eq 'ResetClient') {
                        # Restart the script to clear the client cache and kill the current PowerShell process.
                        Restart-Script
                    }
                    ElseIf ($SystemDisconnectAction -eq 'Lock') {
                        # Lock the computer if they are not KioskUser0. This is a non-autologon scenario.
                        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 526 -Message "Locking the computer." -ErrorAction SilentlyContinue
                        Start-Process -FilePath 'rundll32.exe' -ArgumentList "user32.dll`,LockWorkStation"
                    }
                    ElseIf ($SystemDisconnectAction -eq 'LogOff') {
                        # Logoff the user if they are not KioskUser0. This is a non-autologon scenario.
                        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 527 -Message "Logging off user." -ErrorAction SilentlyContinue
                        Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 0
                    }
                }
                Else {
                    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 582 -Message "There are still active remote desktop sessions. Assuming that user is still active and therefore, not taking action." -ErrorAction SilentlyContinue
                }                
            }
            If ($UserInitiatedEvents) {
                If (Get-MSRDCProcess -eq $false) {
                    If ($UserDisconnectSignOutAction -eq 'ResetClient') {
                        # Restart the script to clear the client cache and kill the current PowerShell process.
                        Restart-Script
                    }
                    ElseIf ($UserDisconnectSignOutAction -eq 'Lock') {
                        # Lock the computer if they are not KioskUser0. This is a non-autologon scenario.
                        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 526 -Message "Locking the computer." -ErrorAction SilentlyContinue
                        Start-Process -FilePath 'rundll32.exe' -ArgumentList "user32.dll`,LockWorkStation"
                    }
                    ElseIf ($UserDisconnectSignOutAction -eq 'LogOff') {
                        # Logoff the user if they are not KioskUser0. This is a non-autologon scenario.
                        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 527 -Message "Logging off user." -ErrorAction SilentlyContinue
                        Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 0
                    }
                }
                Else {
                    # User initiated logoff or disconnection events. Do not take action in this case.
                    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 582 -Message "There are still active remote desktop sessions. Assuming that user is still active and therefore, not taking action." -ErrorAction SilentlyContinue
                }
                Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 578 -Message "There are user initiated logoff or disconnection events." -ErrorAction SilentlyContinue               
            }
            If ($TotalFilteredEvents -eq 0) {
                Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 583 -Message "All 1026 events were filtered out. There is no reason to take action." -ErrorAction SilentlyContinue
            }
        }
    }
    Register-CimIndicationEvent -Query $Query -Action $Action -SourceIdentifier $SourceIdentifier -SupportEvent
}

if ($IdleTimeoutAction -eq 'Logoff' -or $IdleTimeoutAction -eq 'ResetClient') {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 540 -Message "IdleTimeoutAction is configured to '$IdleTimeoutAction'." -ErrorAction SilentlyContinue
    $timer = 0
    $interval = 30 # Check every 30 seconds
    Do {
        if ($IdleTimeoutAction -eq 'ResetClient' -and (Test-Path -Path 'HKCU:\Software\Microsoft\RdClientRadc\Feeds') -or $IdleTimeoutAction -eq 'Logoff') {
            if (-not (Get-Process | Where-Object { $_.Name -eq 'msrdc' })) {
                If ($timer -eq 0) {
                    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 541 -Message "No active connections found. Starting the Idle Timer" -ErrorAction SilentlyContinue
                }
                Else {
                    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 542 -Message "Idle Timer running. Current Idle Time = $($timer) seconds." -ErrorAction SilentlyContinue
                }
                if ($timer -ge $IdleTimeout) {
                    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 543 -Message "Idle timeout: $($IdleTimeout/60) minutes reached." -ErrorAction SilentlyContinue
                    # Perform the action after 15 minutes of inactivity
                    If ($IdleTimeoutAction -eq 'ResetClient') {
                        # Restart the script to clear the client cache and kill the current PowerShell process.
                        Restart-Script
                    }                    
                    Else {
                        # Logoff the user if they are not KioskUser0. This is a non-autologon scenario.
                        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 527 -Message "Logging off user." -ErrorAction SilentlyContinue
                        Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 0
                    }
                }
                $timer += $interval
            }
            else {
                # Reset the timer if the process is found
                If ($timer -gt 0) {
                    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 544 -Message "Remote Desktop connection(s) found. Resetting Idle Timer after $($timer/60) minutes." -ErrorAction SilentlyContinue
                    $timer = 0
                }
            }
        }
        $i = 0
        While ($null -eq $MSRDCW.ExitCode -and $i -ne 6) {
            Start-Sleep -Seconds 5
            $i++
        }
    } Until ($null -ne $MSRDCW.ExitCode)
}
Else {
    # Check again to make sure the MSRDCW window has not been closed. If it has not then wait for the window to exit before continuing.
    Do {
        Start-Sleep -Seconds 5
    } Until ($null -ne $MSRDCW.ExitCode)
}
Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 560 -Message "The Remote Desktop Client closed with exit code [$($MSRDCW.exitcode)]." -ErrorAction SilentlyContinue

If ($Env:UserName -eq 'KioskUser0' -and $MSRDCW.ExitCode -ne -1) {
    # ExitCode -1 is returned when the AVD client is forceably closed with Stop-Process.
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 570 -Message "The Remote Desktop client was closed by the user. Restarting Script." -ErrorAction SilentlyContinue
    Restart-Script  
}
Elseif ($MSRDCW.ExitCode -eq 0) {
    If ($UserDisconnectSignOutAction -eq 'Logoff') {
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 527 -Message "Logging off user." -ErrorAction SilentlyContinue
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 599 -Message "Exiting `"$($MyInvocation.MyCommand.Name)`""
        Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 0
    }
    Elseif ($UserDisconnectSignOutAction -eq 'Lock') {
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 526 -Message "Locking the computer." -ErrorAction SilentlyContinue
        Start-Process -FilePath 'rundll32.exe' -ArgumentList "user32.dll`,LockWorkStation"
    }
    Elseif ($null -eq $DeviceRemovalAction -and $null -eq $IdleTimeoutAction -and $null -eq $SystemDisconnectAction -and $null -eq $UserDisconnectSignOutAction) { 
        # Scenario 3: Restart the system if the user closed the Remote Desktop Client using the [X] at the top right of the window.
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType 'Information' -EventId 595 -Message "The Remote Desktop client was closed by the user. Restarting the system." -ErrorAction SilentlyContinue
        Get-WmiObject -Class Win32_OperatingSystem | Invoke-WmiMethod -Name Win32Shutdown -Argument 2
    }
}