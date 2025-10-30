<# 
.SYNOPSIS
    This script creates a custom Remote Desktop client for Windows kiosk configuration designed to only allow the use of the client.
    It uses a combination of Applocker policies, multi-local group policy settings, Shell Launcher configuration, provisioning packages, and
    registry edits to complete the configuration. There are basically four major options for configuration:

    * Remote Desktop client shell
    * Remote Desktop client shell with autologon
    * Custom Explorer shell (Windows 10) or Multi-App Kiosk Shell (Windows 11)
    * Custom Explorer shell (Windows 10) or Multi-App Kiosk Shell (Windows 11), both with autologon

    These options are controlled by the combination of the two switch parameters - 'ClientShell' and 'Autologon'.
    
    When the RemoteDesktopClientShell switch parameter is not used, then you can utilize the 'ShowSettings' switch parameter to allow access to the Display Settings page.
    
    Additionally, you can choose to

    * Install the latest Remote Desktop client for Windows and Visual C++ Redistributables directly from the web.
    * Monitor for FIDO Passkey device removals and perform the same actions as smart cards such as local computer lock or Remote Desktop
      client reset.

.DESCRIPTION 
    This script completes a series of configuration tasks based on the parameters chosen. These tasks can include:

    * Applocker policy application to block Internet Explorer, Edge, Wordpad, and Notepad
    * Provisioning packages to remove pinned items from the Start Menu for the custom explorer shell option with Windows 10.
    * Provisioning packages to Hide Start Menu elements, disable Windows Spotlight features, and optionally enable SharedPC mode.
    * Built-in application removal.
    * Shell Launcher configuration for the RemoteDesktopClientShell scenarios
    * Multi-App Kiosk configuration for Windows 11 when the RemoteDesktopClientShell switch parameter is not used.
    * Remote Desktop client for Windows install (If selected)
    * Custom Azure Virtual Desktop client shortcuts that launches the Remote Desktop client for Windows
      via a script to enable WMI Event subscription.

.NOTES 
    The script will automatically remove older configurations by running 'Remove-KioskSettings.ps1' during the install process.    

.COMPONENT 
    No PowerShell modules required.

.LINK 
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-windows?tabs=subscribe
    https://learn.microsoft.com/en-us/azure/virtual-desktop/uri-scheme
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview
    https://learn.microsoft.com/en-us/windows/configuration/kiosk-shelllauncher
 
.PARAMETER Autologon
This switch parameter determines If autologon is enabled through the Assigned Access configuration. The Assigned Access feature will automatically
create a new user - 'KioskUser0' - which will not have a password and be configured to automatically logon when Windows starts.

.PARAMETER ClientShell
This switch parameter determines whether the Windows Shell is replaced by the Remote Desktop client for Windows or remains the default 'explorer.exe'.
When the default 'explorer' shell is used additional local group policy settings and provisioning packages are applied to lock down the shell.

.PARAMETER EnvironmentAVD
This value determines the Azure environment to which you are connecting. It ultimately determines the Url of the Remote Desktop Feed which
varies by environment by setting the $SubscribeUrl variable and replacing placeholders in several files during installation.
The list of Urls can be found at
https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-microsoft-store?source=recommendations#subscribe-to-a-workspace.

.PARAMETER InstallRemoteDesktopClient
This switch parameter determines If the latest Remote Desktop client for Windows is automatically downloaded from the Internet and installed
on the system prior to configuration.

.PARAMETER SharedPC
This switch parameter determines If the computer is setup as a shared PC. The account management process is enabled and all user profiles are automatically
deleted on logoff.

.PARAMETER ShowSettings
This switch parameter determines If the Settings App appears on the start menu. The settings app and control panel are restricted to the applets/pages specified in the nonadmins-ShowSettings.txt file. If this value is not set,
then the Settings app and Control Panel are not displayed or accessible.

.PARAMETER DeviceRemovalAction
This string parameter determines what occurs when a FIDO Passkey device or SmartCard is removed from the system. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When 'AutoLogon' is present, you can leave this empty or choose only 'ResetClient'.
When 'AutoLogon' is not present, you can leave this empty or choose 'Lock' or 'Logoff'. You must also use the SmartCard switch parameter or specify a 'DeviceVendorID'.

.PARAMETER DeviceVendorID
This string parameter defines the Vendor ID of the hardware authentication token that if removed will trigger the action defined in "DeviceRemovalAction".
This value is only used when "DeviceRemovalAction" contains a value.

.PARAMETER SmartCard
This switch parameter determines if SmartCard removal will trigger the 'DeviceRemovalAction'. This value is only used when 'DeviceRemovalAction' contains a value.

.PARAMETER IdleTimeoutAction
This string parameter determines what occurs when the system is idle for a specified amount of time. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When 'Autologon' is present, you can leave this empty or choose only 'ResetClient'.
When 'Autologon' is not present, you can leave this empty or choose 'Lock' or 'Logoff'.

.PARAMETER IdleTimeOut
This integer value determines the number of seconds in the that system will wait before performing the action specified in the IdleTimeoutAction parameter.

.PARAMETER SystemDisconnectAction
This string parameter determines what occurs when the remote desktop session connection is disconnected by the system. This could be due to an IdleTimeout on the session host in the SSO scenario or
the user has initiated a connection to the session host from another client. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When 'Autologon' is present, you can leave this empty or choose only 'ResetClient'.
When 'Autologon' is not present, you can leave this empty or choose 'Lock' or 'Logoff'.

.PARAMETER UserDisconnectSignOutAction
This string parameter determines what occurs when the user disconnects or signs out from the remote session. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When 'Autologon' is present, you can leave this empty or choose only 'ResetClient'.
When 'Autologon' is not present, you can leave this empty or choose 'Lock' or 'Logoff'.

.PARAMETER Version
This version parameter allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager or Microsoft Endpoint Configuration Manager by querying the value of the registry value: HKLM\Software\Kiosk\version.

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory, ParameterSetName = 'AutologonClientShell')]
    [Parameter(Mandatory, ParameterSetName = 'DirectLogonClientShell')]
    [switch]$ClientShell,

    [Parameter(Mandatory, ParameterSetName = 'AutologonClientShell')]
    [Parameter(Mandatory, ParameterSetName = 'AutologonExplorerShell')]
    [switch]$Autologon,

    [ValidateSet('AzureChina', 'AzureCloud', 'AzureUSGovernment', 'AzureGovernmentSecret', 'AzureGovernmentTopSecret')]
    [string]$EnvironmentAVD = 'AzureCloud',

    [switch]$InstallRemoteDesktopClient,

    [Parameter(ParameterSetName = 'DirectLogonClientShell')]
    [Parameter(ParameterSetName = 'DirectLogonExplorerShell')]
    [switch]$SharedPC,

    [Parameter(ParameterSetName = 'AutologonExplorerShell')]
    [Parameter(ParameterSetName = 'DirectLogonExplorerShell')]
    [switch]$ShowSettings,

    [ValidateSet('Lock', 'Logoff', 'ResetClient')]
    [string]$DeviceRemovalAction,

    [ValidatePattern("^[0-9A-Fa-f]{4}$")]
    [string]$DeviceVendorID,

    [switch]$SmartCard,

    [ValidateSet('Lock', 'Logoff', 'ResetClient')]
    [string]$IdleTimeoutAction,

    [int]$IdleTimeout = 900,

    [ValidateSet('Lock', 'Logoff', 'ResetClient')]
    [string]$SystemDisconnectAction,

    [ValidateSet('Lock', 'Logoff', 'ResetClient')]
    [string]$UserDisconnectSignOutAction,

    [version]$Version = '7.0.0'
)

#region Parameter Validation and Configuration
$ActionParameters = @($DeviceRemovalAction, $IdleTimeoutAction, $SystemDisconnectAction, $UserDisconnectSignOutAction)
If ($Autologon) {
    ForEach ($Action in $ActionParameters) {
        If ($null -ne $Action) {
            If ($Action -eq 'Lock' -or $Action -eq 'Logoff') {
                Throw "You cannot specify a TriggerAction of Lock or Logoff with AutoLogon"
            }
        }
    }
}
Else {
    ForEach ($Action in $ActionParameters) {
        If ($null -ne $Action) {
            If ($Action -eq 'ResetClient') {
                Throw "You cannot specify a TriggerAction of ResetClient without AutoLogon"
            }
        }
    }
    If ($DeviceRemovalAction -and $SmartCard -eq $false -and ($null -eq $DeviceVendorID)) {
        Throw 'You must specify either a DeviceVendorID or SmartCard when DeviceRemoval is a trigger.'
    }
    ElseIf ($DeviceRemovalAction -and $SmartCard -and ($null -ne $DeviceVendorID -and $DeviceVendorID -ne '')) {
        Throw 'You cannot specify both a SmartCard and DeviceVendorID when the Triggers contain "DeviceRemoval"'
    }
}
#endegion

# Restart in 64-Bit PowerShell if not already running in 64-bit mode
# primarily designed to support Microsoft Endpoint Manager application deployment
If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    $scriptArguments = $null
    Try {
        foreach ($k in $PSBoundParameters.keys) {
            switch ($PSBoundParameters[$k].GetType().Name) {
                "SwitchParameter" { If ($PSBoundParameters[$k].IsPresent) { $scriptArguments += "-$k " } }
                "String" { If ($PSBoundParameters[$k] -match '_') { $scriptArguments += "-$k `"$($PSBoundParameters[$k].Replace('_',' '))`" " } Else { $scriptArguments += "-$k `"$($PSBoundParameters[$k])`" " } }
                "String[]" { $ScriptArguments += "-$k `"$($PSBoundParameters[$k] -join '`",`"')`" " }
                "Int32" { $scriptArguments += "-$k $($PSBoundParameters[$k]) " }
                "Boolean" { $scriptArguments += "-$k `$$($PSBoundParameters[$k]) " }
                "Version" { $scriptArguments += "-$k `"$($PSBoundParameters[$k])`" " }
            }
        }
        If ($null -ne $scriptArguments) {
            $RunScript = Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$PSCommandPath`" $scriptArguments" -PassThru -Wait -NoNewWindow
        }
        Else {
            $RunScript = Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$PSCommandPath`"" -PassThru -Wait -NoNewWindow
        }
    }
    Catch {
        Throw "Failed to start 64-bit PowerShell"
    }
    Exit $RunScript.ExitCode
}

$Script:FullName = $MyInvocation.MyCommand.Path
$Script:Dir = Split-Path $Script:FullName
# Windows Event Log (.evtx)
$EventLog = 'Remote-Desktop-Client-Kiosk'
$EventSource = 'Configuration'
# Find LTSC OS (and Windows IoT Enterprise)
$OS = Get-WmiObject -Class Win32_OperatingSystem
# Detect Windows 11
If ($OS.Name -match 'LTSC') { $LTSC = $true }
# Source Directories and supporting files
$DirAppLocker = Join-Path -Path $Script:Dir -ChildPath 'AppLocker'
$DirApps = Join-Path -Path $Script:Dir -ChildPath 'Apps'
$DirAssignedAccess = Join-Path -Path $Script:Dir -ChildPath 'AssignedAccess'
$DirMultiAppSettings = Join-Path -Path $DirAssignedAccess -ChildPath 'MultiApp'
$DirShellLauncherSettings = Join-Path -Path $DirAssignedAccess -ChildPath "ShellLauncher"
$DirProvisioningPackages = Join-Path -Path $Script:Dir -ChildPath "ProvisioningPackages"
$DirGPO = Join-Path -Path $Script:Dir -ChildPath "GPOSettings"
$DirKiosk = Join-Path -Path $env:SystemDrive -ChildPath "KioskSettings"
$DirTools = Join-Path -Path $Script:Dir -ChildPath "Tools"
$DirUserLogos = Join-Path -Path $Script:Dir -ChildPath "UserLogos"
$DirCustomLaunchScript = Join-Path -Path $Script:Dir -ChildPath "Scripts\CustomLaunchScript"
$DirSchedTasksScripts = Join-Path -Path $Script:Dir -ChildPath "Scripts\ScheduledTasks"
$DirFunctions = Join-Path -Path $Script:Dir -ChildPath "Scripts\Functions"

# Set AVD feed subscription Url.
Switch ($EnvironmentAVD) {
    'AzureChina' { $SubscribeUrl = 'https://rdweb.wvd.azure.cn/api/arm/feeddiscovery' }
    'AzureCloud' { $SubscribeUrl = 'https://rdweb.wvd.azure.com/api/arm/feeddiscovery' }
    'AzureUSGovernment' { $SubscribeUrl = 'https://rdweb.wvd.azure.us/api/arm/feeddiscovery' }
    'AzureGovernmentSecret' { $SubscribeUrl = 'https://rdweb.wvd.<CLOUDSUFFIX>/api/arm/feeddiscovery' }
    'AzureGovernmentTopSecret' { $SubscribeUrl = 'https://rdweb.wvd.<CLOUDSUFFIX>/api/arm/feeddiscovery' }
}

If ($null -ne $DeviceVendorID -and $DeviceVendorID -ne '') {
    $SecurityKey = $true
}
# Only create the custom launch shortcut when necessary. It is only necessary any of the following conditions are true:
# 1. 'Autologon' is enabled (Scenario 2)
# 2. 'SystemDisconnectAction' or 'UserDisconnectSignOutAction' is defined
# 3. 'IdleTimeoutAction' is 'Logoff'
# 4. 'DeviceRemovalAction' is defined and a 'DeviceVendorId' is defined
# 5. None of the available triggers and actions are defined ('DeviceRemovalAction', 'IdleTimeoutAction', or 'SystemDisconnectAction', or 'UserDisconnectSignOutAction'). (Scenario 3)

If ($Autologon -or $IdleTimeoutAction -eq 'Logoff' -or $SystemDisconnectAction -or $UserDisconnectSignOutAction -or ($DeviceRemovalAction -and $SecurityKey) -or (-not $Autologon -and ($null -eq $DeviceRemovalAction -and $null -eq $IdleTimeoutAction -and $null -eq $SystemDisconnectAction -and $null -eq $UserDisconnectSignOutAction))) {
    $CustomLaunchScript = $true
}
    
# Set default exit code to 0
$ScriptExitCode = 0

#region Load Functions

If (Test-Path -Path $DirFunctions) {
    $Functions = Get-ChildItem -Path $DirFunctions -Filter '*.ps1'
    ForEach ($Function in $Functions) {
        Try {
            . "$($Function.FullName)"
        }
        Catch {
            Write-Error "Failed to load function from $($Function.FullName): $($_.Exception.Message)"
            Exit 1
        }
    }
}
Else {
    Write-Error "Functions directory not found at: $DirFunctions"
    Exit 1
}

#endregion Functions

#region Initialization
New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction SilentlyContinue
Write-Output "Waiting 5 seconds for event log to be ready..."
# Wait for event log to be ready
Start-Sleep -Seconds 5

$message = @"
Starting Remote Desktop Client Kiosk Configuration Script
Script Full Name: $($Script:FullName)
Parameters:
    $($PSBoundParameters | Out-String)
Running on: $($OS.Caption) version $($OS.Version)
"@
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 1 -Message $message

If (Get-PendingReboot) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Error -EventId 0 -Message "There is a reboot pending. This application cannot be installed when a reboot is pending.`nRebooting the computer in 15 seconds."
    Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r /t 15'
    Exit 2
}

# Copy lgpo to system32 for future use.
Copy-Item -Path "$DirTools\lgpo.exe" -Destination "$env:SystemRoot\System32" -Force | Out-Null

# Enable the Scheduled Task History by enabling the TaskScheduler operational log
$TaskschdLog = Get-WinEvent -ListLog Microsoft-Windows-TaskScheduler/Operational
$TaskschdLog.IsEnabled = $True
$TaskschdLog.SaveChanges()

#endregion Inistiialization

#region Remove Previous Versions

# Run Removal Script first in the event that a previous version is installed or in the event of a failed installation.
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 3 -Message 'Running removal script in case of previous installs or failures.'
& "$Script:Dir\Remove-KioskSettings.ps1"

#endregion Previous Version Removal

#region Remove Apps

# Remove Built-in Windows 10 Apps on non LTSC builds of Windows
If (-not $LTSC) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 25 -Message "Starting Remove Apps Script."
    Remove-BuiltInApps
}

# Remove OneDrive
If (Test-Path -Path "$env:SystemRoot\Syswow64\onedrivesetup.exe") {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 26 -Message "Removing Per-User installation of OneDrive."
    Start-Process -FilePath "$env:SystemRoot\Syswow64\onedrivesetup.exe" -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
    $OneDrivePresent = $true
}
ElseIf (Test-Path -Path "$env:ProgramFiles\Microsoft OneDrive") {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 26 -Message "Removing Per-Machine Installation of OneDrive."
    $OneDriveSetup = Get-ChildItem -Path "$env:ProgramFiles\Microsoft OneDrive" -Filter 'onedrivesetup.exe' -Recurse
    If ($OneDriveSetup) {
        Start-Process -FilePath $OneDriveSetup[0].FullName -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
        $OneDrivePresent = $true
    }
}
#endregion Remove Apps

#region Install Remote Desktop Client
If ($InstallRemoteDesktopClient) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventID 30 -Message "Running Script to install or update Visual C++ Redistributables."
    & "$DirApps\VisualC++Redistributables\Install-VisualC++Redistributables.ps1"
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 31 -Message "Running Script to install or update the Remote Desktop Client."
    & "$DirApps\RemoteDesktopClient\Install-RemoteDesktopClient.ps1"
}
#endregion Install Remote Desktop Client

#region KioskSettings Directory

#Create the KioskSettings Directory
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 40 -Message "Creating KioskSettings Directory at root of system drive."
If (-not (Test-Path $DirKiosk)) {
    New-Item -Path $DirKiosk -ItemType Directory -Force | Out-Null
}

# Setting ACLs on the Kiosk Settings directory to prevent Non-Administrators from changing files. Defense in Depth.
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 41 -Message "Configuring Kiosk Directory ACLs"
$Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
$ACL = Get-ACL $DirKiosk
$ACL.SetOwner($Group)
Set-ACL -Path $DirKiosk -AclObject $ACL
Update-ACL -Path $DirKiosk -Identity 'BuiltIn\Administrators' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'BuiltIn\Users' -FileSystemRights 'ReadAndExecute' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'System' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACLInheritance -Path $DirKiosk -DisableInheritance $true -PreserveInheritedACEs $false

# Copy Client Launch Scripts.
If ($CustomLaunchScript) {
    $LaunchScriptSource = 'Launch AVD Client'
    New-EventLog -LogName $EventLog -Source $LaunchScriptSource -ErrorAction SilentlyContinue
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 42 -Message "Copying Launch AVD Client Scripts from '$DirCustomLaunchScript' to '$DirKiosk'"
    Copy-Item -Path "$DirCustomLaunchScript\*" -Destination $DirKiosk -Force | Out-Null
    # dynamically update parameters of launch script.
    $FileToUpdate = Join-Path -Path $DirKiosk -ChildPath 'Launch-AVDClient.ps1'
    $Content = Get-Content -Path $FileToUpdate
    $Content = $Content.Replace('[string]$EventLog', "[string]`$EventLog = '$EventLog'") 
    $Content = $Content.Replace('[string]$EventSource', "[string]`$EventSource = '$LaunchScriptSource'")
    If ($Autologon) {
        $Content = $Content.Replace('[string]$SubscribeUrl', "[string]`$SubscribeUrl = '$SubscribeUrl'")
    }
    If ($SecurityKey) { $Content = $Content.Replace('[string]$DeviceVendorID', "[string]`$DeviceVendorID = '$DeviceVendorID'") }
    If ($SmartCard) { $Content = $Content.Replace('[bool]$SmartCard', '[bool]$SmartCard = $true') }
    If ($IdleTimeout) { $Content = $Content.Replace('[int]$IdleTimeout', "[int]`$IdleTimeout = $IdleTimeout") }
    If ($DeviceRemovalAction) { $Content = $Content.Replace('[string]$DeviceRemovalAction', "[string]`$DeviceRemovalAction = '$DeviceRemovalAction'") }
    if ($IdleTimeoutAction) { $Content = $Content.Replace('[string]$IdleTimeoutAction', "[string]`$IdleTimeoutAction = '$IdleTimeoutAction'") }
    If ($SystemDisconnectAction) { $Content = $Content.Replace('[string]$SystemDisconnectAction', "[string]`$SystemDisconnectAction = '$SystemDisconnectAction'") }
    if ($UserDisconnectSignOutAction) { $Content = $Content.Replace('[string]$UserDisconnectSignOutAction', "[string]`$UserDisconnectSignOutAction = '$UserDisconnectSignOutAction'") }    
    $Content | Set-Content -Path $FileToUpdate
}
If ($Autologon) {
    $SchedTasksScriptsDir = Join-Path -Path $DirKiosk -ChildPath 'ScheduledTasks'
    If (-not (Test-Path $SchedTasksScriptsDir)) {
        $null = New-Item -Path $SchedTasksScriptsDir -ItemType Directory -Force
    }
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 43 -Message "Copying Scheduled Task Scripts from '$DirSchedTasksScripts' to '$SchedTasksScriptsDir'"
    Get-ChildItem -Path $DirSchedTasksScripts -filter '*.*' | Copy-Item -Destination $SchedTasksScriptsDir -Force
}
If ($SystemDisconnectAction -or $UserDisconnectSignOutAction) {
    $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\EventLog", $true)
    $null = $parentKey.CreateSubKey("Microsoft-Windows-TerminalServices-RDPClient/Operational")
}
#endregion KioskSettings Directory

#region Provisioning Packages

$ProvisioningPackages = @()

Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 44 -Message "Adding Provisioning Package to disable Windows Spotlight"
$ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'DisableWindowsSpotlight.ppkg'

Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 44 -Message "Adding Provisioning Package to disable first sign-in animation"
$ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'DisableFirstLogonAnimation.ppkg'

If ($SharedPC) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 44 -Message "Adding Provisioning Package to enable SharedPC mode"
    $ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'SharedPC.ppkg'
}

If (!$ClientShell) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 44 -Message "Adding Provisioning Package to hide Start Menu Elements"
    $ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'HideStartMenuElements.ppkg'
}

New-Item -Path "$DirKiosk\ProvisioningPackages" -ItemType Directory -Force | Out-Null
ForEach ($Package in $ProvisioningPackages) {
    Copy-Item -Path $Package -Destination "$DirKiosk\ProvisioningPackages" -Force
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventID 46 -Message "Installing $($Package)."
    Install-ProvisioningPackage -PackagePath $Package -ForceInstall -QuietInstall
}

#endregion Provisioning Packages

#region Start Menu

If (-not ($ClientShell)) {
    # Create custom Remote Desktop Client shortcut and configure custom start menu for Non-Admins
    [string]$StringVersion = $Version
    $ObjShell = New-Object -ComObject WScript.Shell
    $DirShortcut = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    $LinkRemoteDesktop = "Remote Desktop.lnk"
    $PathLinkRD = Join-Path $DirShortcut -ChildPath $LinkRemoteDesktop
        
    If ($CustomLaunchScript) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 48 -Message "Creating a custom AVD Shortcut in Start Menu."
        $LinkAVD = "Azure Virtual Desktop.lnk"    
        $ShortcutPath = Join-Path $DirShortcut -ChildPath $LinkAVD
        $Shortcut = $ObjShell.CreateShortcut($ShortcutPath)
        #Set values
        $Shortcut.TargetPath = "wscript.exe"
        $Shortcut.Arguments = "`"$env:SystemDrive\KioskSettings\Launch-AVDClient.vbs`""
        $Shortcut.WindowStyle = 3
        $Shortcut.WorkingDirectory = "$env:ProgramFiles\Remote Desktop"
        $Shortcut.Description = "Launches Remote Desktop Client and logon prompt. Kiosk Configuration Version: $StringVersion"
        $Shortcut.IconLocation = $ObjShell.CreateShortcut($PathLinkRD).IconLocation
        $Shortcut.Save()
    }
    Else {
        # Do not need special Remote Desktop Client shortcut if not using 'Autologon' or a Device Other than SmartCards. Updating it to start maximized.
        $ShortcutPath = $PathLinkRD
        $Shortcut = $ObjShell.CreateShortcut($ShortcutPath)
        $Shortcut.WindowStyle = 3
        $Shortcut.Save()
    }  
    
    $dirStartup = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    If (-not (Test-Path -Path $dirStartup)) {
        $null = New-Item -Path $dirStartup -ItemType Directory -Force
    }
    Copy-Item -Path "$ShortcutPath" -Destination $dirStartup -Force   
}
    
#endregion Start Menu

#region User Logos
If ($Autologon) {
    $null = cmd /c lgpo.exe /t "$DirGPO\computer-userlogos.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 55 -Message "Configured User Logos to use default via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 56 -Message "Backing up current User Logo files to '$DirKiosk\UserLogos'."
    Copy-Item -Path "$env:ProgramData\Microsoft\User Account Pictures" -Destination "$DirKiosk\UserLogos" -Force
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 57 -Message "Copying User Logo files to '$env:ProgramData\Microsoft\User Account Pictures'."
    Get-ChildItem -Path $DirUserLogos | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force
}
#endregion User Logos

#region Local GPO Settings

If ($ClientShell) {
    $nonAdminsFile = 'nonadmins-RemoteDesktopClientShell.txt'
    $null = cmd /c lgpo.exe /t "$DirGPO\$nonAdminsFile" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 60 -Message "Configured basic Explorer settings for kiosk user via Non-Administrators Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    $computerFile = 'computer-RemoteDesktopClientShell.txt'
    $null = cmd /c lgpo.exe /t "$DirGPO\$computerFile" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 61 -Message "Disabled New User Privacy Experience via Computer Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
}
ElseIf ($ShowSettings) {
    $null = cmd /c lgpo.exe /t "$DirGPO\nonadmins-ShowSettings.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 63 -Message "Restricted Settings App and Control Panel to allow only Display Settings for kiosk user via Non-Administrators Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
}


# Configure Feed URL for Autologon User
If ($Autologon) {
    $outfile = "$env:Temp\Users-AVDURL.txt"
    $sourceFile = Join-Path -Path $DirGPO -ChildPath 'users-DefaultConnectionUrl.txt'
    (Get-Content -Path $sourceFile).Replace('<url>', $SubscribeUrl) | Out-File $outfile
    $null = cmd /c lgpo.exe /t "$outfile" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 70 -Message "Configured Default Connection URL for autologon user via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    # Disable Password requirement for screen saver lock and wake from sleep.
    $null = cmd /c lgpo.exe /t "$DirGPO\disablePasswordForUnlock.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 80 -Message "Disabled password requirement for screen saver lock and wake from sleep via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    $null = cmd /c lgpo.exe /t "$DirGPO\nonadmins-autologon.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 81 -Message "Removed logoff, change password, lock workstation, and fast user switching entry points. `nlgpo.exe Exit Code: [$LastExitCode]"
}
Else {
    If ($DeviceRemovalAction -and $SmartCard) {
        If ($DeviceRemovalAction -eq 'Lock') {
            $null = cmd /c lgpo /s "$DirGPO\SmartCardLockWorkstation.inf" '2>&1'
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Lock Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
        }
        ElseIf ($DeviceRemovalAction -eq 'Logoff') {
            $null = cmd /c lgpo /s "$DirGPO\SmartCardLogOffWorkstation.inf" '2>&1'
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Force Logoff Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
        }
    }
    If ($IdleTimeoutActon -eq 'Lock') {
        # Will lock the system via the inactivity timeout built-in policy which locks the screen after inactivity.
        $sourceFile = Join-Path -Path $DirGPO -ChildPath 'MachineInactivityTimeout.inf'
        $outFile = Join-Path -Path $env:Temp -ChildPath 'MachineInactivityTimeout.inf'
        (Get-Content -Path $SourceFile).Replace('900', $IdleTimeout) | Out-File $outFile
        $null = cmd /c lgpo /s "$outFile" '2>&1'
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 85 -Message "Set 'Interactive logon: Machine inactivity limit' to '$IdleTimeout seconds' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    }
}

#endregion Local GPO Settings

#region Registry Edits

$RegValues = @()

$RegValues += [PSCustomObject]@{
    Path         = 'HKCU:\Software\Microsoft\RDclientRadc'
    Name         = 'EnableMSRDCTelemetry'
    PropertyType = 'DWord'
    Value        = 0
    Description  = 'Disable Remote Desktop client telemetry data'
}

$RegValues += [PSCustomObject]@{
    Path         = 'HKLM:\SOFTWARE\Microsoft\MSRDC\Policies'
    Name         = 'AutomaticUpdates'
    PropertyType = 'DWord'
    Value        = 0
    Description  = 'Disable Updates and Notifications in Remote Desktop Client'
}

$RegValues += [PSCustomObject]@{
    Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'
    Name         = 'BlockAADWorkplaceJoin'
    PropertyType = 'DWord'
    Value        = 1
    Description  = 'Disable "Stay Signed in to all your apps" pop-up'
}


If (-not $Autologon) {
    #https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotedesktop#autosubscription
    $RegValues += [PSCustomObject]@{
        Path         = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Name         = 'AutoSubscription'
        PropertyType = 'String'
        Value        = "$SubscribeUrl"
        Description  = 'AVD Client Subscription URL'
    }
}

If ($OneDrivePresent) {
    $RegValues += [PSCustomObject]@{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        Name         = 'OneDriveSetup'
        PropertyType = 'String'
        Value        = ''
        Description  = 'Remove OneDriveSetup from starting for each user.'
    }
}

If (-not $ClientShell) {
    $RegValues += [PSCustomObject]@{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Name         = 'StartShownOnUpgrade'
        PropertyType = 'DWord'
        Value        = 1
        Description  = 'Disable Start Menu from opening automatically'
    }
}

# create the reg key restore file if it doesn't exist, else load it to compare for appending new rows.
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 97 -Message "Creating a Registry key restore file for Kiosk Mode uninstall."
$FileRestore = "$DirKiosk\RegKeyRestore.csv"
New-Item -Path $FileRestore -ItemType File -Force | Out-Null
Add-Content -Path $FileRestore -Value 'Path,Name,PropertyType,Value,Description'

# Check if any registry keys require HKCU access before loading the hive     
If ($RegValues | Where-Object { $_.Path -like 'HKCU:*' }) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 11 -EntryType Information -Message "Loading Default User Hive for HKCU registry operations."
    Start-Process -FilePath "REG.exe" -ArgumentList "LOAD", "HKLM\Default", "$env:SystemDrive\Users\default\ntuser.dat" -Wait
}

# Loop through the registry key file and perform actions.
ForEach ($Entry in $RegValues) {
    #reset from previous values
    $Path = $null
    $Name = $null
    $PropertyType = $null
    $Value = $null
    $Description = $Null
    $PathHKLM = $null
    #set values
    $Path = $Entry.Path
    $Name = $Entry.Name
    $PropertyType = $Entry.PropertyType
    $Value = $Entry.Value
    $Description = $Entry.Description
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 99 -Message "Processing Registry Value to '$Description'."

    If ($Path -like 'HKCU:*') {
        $PathHKLM = $Path.Replace("HKCU:\", "HKLM:\Default\")
    } Else {
        $PathHKLM = $Path
    }
    $CurrentRegValue = $null
    If (Get-ItemProperty -Path $PathHKLM -Name $Name -ErrorAction SilentlyContinue) {
        $CurrentRegValue = Get-ItemPropertyValue -Path $PathHKLM -Name $Name
        Add-Content -Path $FileRestore -Value "$Path,$Name,$PropertyType,$CurrentRegValue"
    }
    Else {
        Add-Content -Path $FileRestore -Value "$Path,$Name,,"
    }

    If ($Value -ne '' -and $null -ne $Value) {
        # This is a set action
        Set-RegistryValue -Path $PathHKLM -Name $Name -PropertyType $PropertyType -Value $Value       
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 100 -Message "Setting '$PropertyType' Value '$Name' with Value '$Value' to '$Path'"
    }
    Elseif ($CurrentRegValue) {     
        Remove-ItemProperty -Path $PathHKLM -Name $Name -ErrorAction SilentlyContinue
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 102 -Message "Deleted Value '$Name' from '$Path'."
    }               
}    

If (Test-Path -Path 'HKLM:\Default') {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 103 -Message "Unloading Default User Hive Registry Keys via Reg.exe."
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 5
    $RegUnload = Start-Process 'reg.exe' -ArgumentList 'UNLOAD', 'HKLM\Default' -Wait -NoNewWindow -PassThru
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 104 -Message "Reg.exe Exit Code: [$($RegUnload.ExitCode)]"
}

#endregion Registry Edits

#region Applocker Policy

If ($ClientShell) {
    # With Shell Launcher, we need to use applocker to block access to other applications which could be launched from the Remote Desktop Client.
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 110 -Message "Applying AppLocker Policy to disable Microsoft Edge, Internet Explorer, Notepad, and Wordpad for the Kiosk User."
    # If there is an existing applocker policy, back it up and store its XML for restore.
    # Else, copy a blank policy to the restore location.
    # Then apply the new AppLocker Policy
    $FileAppLockerKiosk = Join-Path -Path $DirAppLocker -ChildPath "ClientShellAppLockerPolicy.xml"
    [xml]$Policy = Get-ApplockerPolicy -Local -XML
    If ($Policy.AppLockerPolicy.RuleCollection) {
        Get-ApplockerPolicy -Local -XML | out-file "$DirKiosk\ApplockerPolicy.xml" -force
    }
    Else {
        Copy-Item -Path (Join-Path -Path $DirAppLocker -ChildPath "ClearAppLockerPolicy.xml") -Destination "$DirKiosk\ApplockerPolicy.xml" -Force | Out-Null
    }
    Set-AppLockerPolicy -XmlPolicy "$FileAppLockerKiosk"
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 111 -Message "Enabling and Starting Application Identity Service"
    Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
    # Start the service if not already running
    If ((Get-Service -Name AppIDSvc).Status -ne 'Running') {
        Start-Service -Name AppIDSvc
    }
}

#endregion Applocker Policy

#region Shell Launcher Configuration

Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Starting Assigned Access Configuration Section."

If ($ClientShell) {
    If ($Autologon) {
        $ConfigFile = "Launch-AVDClient_AutoLogon.xml"
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 114 -Message "Enabling Custom AVD Client Launch Script Shell Launcher Settings with Autologon via WMI MDM bridge."
    }
    ElseIf ($CustomLaunchScript) {
        $ConfigFile = "Launch-AVDClient.xml"
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 114 -Message "Enabling Custom AVD Client Launch Script Shell Launcher Settings for Security Keys via WMI MDM bridge."
    }
    Else {
        $ConfigFile = "msrdcw.xml"
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 114 -Message "Enabling Remote Desktop Client Shell Launcher Settings via WMI MDM bridge."
    }
    $SourceFile = Join-Path $DirShellLauncherSettings -ChildPath $ConfigFile
    $DestFile = Join-Path -Path $DirKiosk -ChildPath "ShellLauncher.xml"
    Copy-Item -Path $SourceFile -Destination $DestFile -Force | Out-Null
    Set-AssignedAccessShellLauncher -FilePath $DestFile
    If (Get-AssignedAccessShellLauncher) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 115 -Message "Shell Launcher configuration successfully applied."
    }
    Else {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Error -EventId 116 -Message "Shell Launcher configuration failed. Computer should be restarted first."
        Exit 1
    }
}
Else {
    If ($Autologon) {
        If ($ShowSettings) {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Custom Launch Script with Settings and Autologon."
            $ConfigFile = "AzureVirtualDesktop_Settings_Autologon.xml"
        }
        Else {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Custom Launch Script and Autologon."
            $ConfigFile = "AzureVirtualDesktop_Autologon.xml"
        }
    }
    Else {
        If ($ShowSettings) {
            If ($CustomLaunchScript) {
                Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Custom Launch Script with Settings."
                $ConfigFile = "AzureVirtualDesktop_Settings.xml"
            }
            Else {
                Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Remote Desktop Client and Settings."
                $ConfigFile = "RemoteDesktop_Settings.xml"
            }
        }
        Else {
            If ($CustomLaunchScript) {
                Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Custom Launch Script."
                $ConfigFile = "AzureVirtualDesktop.xml"
            }
            Else {
                Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Remote Desktop Client."
                $ConfigFile = "RemoteDesktop.xml"
            }
        }
    }
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 114 -Message "Configuration File = $ConfigFile"
    $SourceFile = Join-Path -Path $DirMultiAppSettings -ChildPath $ConfigFile
    $DestFile = Join-Path $DirKiosk -ChildPath 'MultiAppKioskConfiguration.xml'
    Copy-Item -Path $SourceFile -Destination $DestFile -Force | Out-Null
    Set-AssignedAccessConfiguration -FilePath $DestFile
    If (Get-AssignedAccessConfiguration) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 115 -Message "Multi-App Kiosk configuration successfully applied."
    }
    Else {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Error -EventId 116 -Message "Multi-App Kiosk configuration failed. Computer should be restarted first."
        Exit 1        
    }
}

#endregion Assigned Access Launcher

#region Prevent Microsoft AAD Broker Timeout

If ($Autologon) {
    $TaskName = "(AVD Client) - Restart AAD Sign-in"
    $TaskDescription = 'Restarts the AAD Sign-in process if there are no active connections to prevent a stale sign-in attempt.'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 135 -Message "Creating Scheduled Task: '$TaskName'."
    $TaskScriptEventSource = 'AAD Sign-in Restart'
    New-EventLog -LogName $EventLog -Source $TaskScriptEventSource -ErrorAction SilentlyContinue
    $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn -User KioskUser0
    $TaskTrigger.Delay = 'PT30M'
    $TaskTrigger.Repetition = (New-ScheduledTaskTrigger -Once -At "12:00 AM" -RepetitionInterval (New-TimeSpan -Minutes 30)).Repetition
    $TaskAction = New-ScheduledTaskAction -Execute "wscript.exe" `
        -Argument "$SchedTasksScriptsDir\Restart-AADSignIn.vbs"
    # Set up scheduled task to run interactively (only when user is logged in)
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId KioskUser0 -LogonType Interactive
    $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -Compatibility Win8 -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Description $TaskDescription -Principal $TaskPrincipal -Settings $TaskSettings -Trigger $TaskTrigger
    If (Get-ScheduledTask | Where-Object { $_.TaskName -eq "$TaskName" }) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 119 -Message "Scheduled Task created successfully."
    }
    Else {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Error -EventId 120 -Message "Scheduled Task not created."
        $ScriptExitCode = 1618
    }
}

#endregion Prevent Microsoft AAD Broker Timeout
If ($ScriptExitCode -eq 1618) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Error -EventId 135 -Message "At least one critical failure occurred. Exiting Script and restarting computer."
    Restart-Computer -Force
}
Else {
    $ScriptExitCode = 0
}
    
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 150 -Message "Updating Group Policy"
$GPUpdate = Start-Process -FilePath 'GPUpdate' -ArgumentList '/force' -Wait -PassThru
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventID 151 -Message "GPUpdate Exit Code: [$($GPUpdate.ExitCode)]"
Set-RegistryValue -Path 'HKLM:\Software\Kiosk' -Name 'Version' -PropertyType 'String' -Value $($version.ToString())
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 199 -Message "Ending Kiosk Mode Configuration version '$($version.ToString())' with Exit Code: $ScriptExitCode"
Exit $ScriptExitCode