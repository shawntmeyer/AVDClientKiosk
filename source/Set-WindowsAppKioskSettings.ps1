<# 
.SYNOPSIS
    This script creates a custom Windows App (Microsoft Remote Desktop) kiosk configuration designed to only allow the use of the Windows App.
    It uses a combination of Assigned Access policies, multi-local group policy settings, provisioning packages, and registry edits to complete 
    the configuration. There are basically four major configuration scenarios:

    * Single-app kiosk mode with Windows App as the dedicated application
    * Single-app kiosk mode with Windows App as the dedicated application and autologon
    * Multi-app kiosk mode with restricted Start menu and taskbar access
    * Multi-app kiosk mode with restricted Start menu and taskbar access with autologon

    These options are controlled by the combination of the SingleAppKiosk and AutoLogonKiosk switch parameters.
    
    When the SingleAppKiosk switch parameter is not used, you can utilize the ShowSettings switch parameter to allow access to the Settings app.
    
    Additionally, you can choose to:

    * Provision the latest Windows App directly from the Microsoft download site so that it is installed for every user.
    * Configure automatic logoff behavior for the Windows App in kiosk scenarios.
    * When not configured as an autologon kiosk:
        * Monitor for smart card removals and perform lock or logoff actions.
        * Enable SharedPC mode for automatic profile cleanup.

.DESCRIPTION 
    This script completes a series of configuration tasks based on the parameters chosen. These tasks can include:

    * Assigned Access configuration for single-app or multi-app kiosk modes
    * Windows App provisioning from the Microsoft download site or via a local source file.
    * Automatic logoff and app reset configuration for Windows App
    * Multi-Local Group Policy configuration to limit interface elements and restrict access
    * Provisioning packages to Hide Start Menu elements and optionally enable SharedPC mode for automatic profile cleanup
    * Built-in application removal to reduce attack surface and speed logon.
    * Start menu and taskbar customization for multi-app kiosk scenarios
    * Smart card removal behavior configuration (lock or logoff)
    * Registry modifications to enforce kiosk behavior and settings

.NOTES 
    The script will automatically remove older configurations by running 'Remove-KioskSettings.ps1' during the install process.    

.COMPONENT 
    No PowerShell modules required.

.LINK 


.PARAMETER AutoLogonKiosk
This switch parameter determines If autologon is enabled through the Assigned Access configuration. The Assigned Access feature will automatically
create a new user - 'KioskUser0' - which will not have a password and be configured to automatically logon when Windows starts.

.PARAMETER WindowsAppAutoLogoffConfig
This string parameter determines the automatic logoff configuration for the Windows App when the AutoLogonKiosk switch parameter is used. The possible values are:
* Disabled - Disables automatic sign-out and app data reset for the Windows App. (Not RECOMMENDED for Kiosk scenarios)
* ResetAppOnCloseOnly - Sign all users out of Windows App and reset app data when the user closes the app.
* ResetAppAfterConnection - Sign all users out of Windows App and reset app data when a successful connection to an Azure Virtual Desktop session host or Windows 365 Cloud PC is made.
* ResetAppOnCloseOrIdle - Sign all users out of Windows App and reset app data when the operating system is idle for the specified time interval in minutes or the user closes the app.

.PARAMETER WindowsAppAutoLogoffTimeInterval
This integer value determines the interval at which Windows App checks the Windows OS for inactivity.
For example, if set to 5, the app will poll the OS for inactivity every 5 minutes and the logout process will initiate if the OS reports 5 or more minutes of inactivity. 

.PARAMETER WindowsAppShell
This switch parameter determines whether the Windows Shell is replaced by the Windows App or remains the default 'explorer.exe'.

.PARAMETER InstallWindowsApp
This switch parameter determines If the latest Remote Desktop client for Windows is automatically downloaded from the Internet and installed
on the system prior to configuration.

.PARAMETER SharedPC
This switch parameter determines If the computer is setup as a shared PC. The account management process is enabled and all user profiles are automatically
deleted on logoff.

.PARAMETER ShowSettings
This switch parameter determines If the Settings App appears on the start menu. The settings app and control panel are restricted to the applets/pages specified in the nonadmins-ShowSettings.txt file. If this value is not set,
then the Settings app and Control Panel are not displayed or accessible.

.PARAMETER LockScreenAfterSeconds
This integer value determines the number of seconds of idle time before the lock screen is displayed. This parameter is only valid when the AutoLogonKiosk switch parameter is not used.

.PARAMETER SmartCardRemovalAction   
This string parameter determines what occurs when the smart card that was used to authenticate to the operating system is removed from the system. The possible values are 'Lock' or 'Logoff'.
When AutoLogon is true, this parameter cannot be used.

.PARAMETER Version
This version parameter allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager or Microsoft Endpoint Configuration Manager by querying the value of the registry value: HKLM\Software\Kiosk\version.

#>
[CmdletBinding()]
param (
    [switch]$InstallWindowsApp,

    [Parameter(Mandatory, ParameterSetName = 'AutologonShellLauncher')]
    [Parameter(Mandatory, ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [switch]$AutoLogonKiosk,

    [Parameter(Mandatory, ParameterSetName = 'AutologonShellLauncher')]
    [Parameter(Mandatory, ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [ValidateSet('Disabled', 'ResetAppOnCloseOnly', 'ResetAppAfterConnection', 'ResetAppOnCloseOrIdle')]
    [string]$WindowsAppAutoLogoffConfig,

    [Parameter(Mandatory = $false, ParameterSetName = 'AutologonShellLauncher')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [int]$WindowsAppAutoLogoffTimeInterval,

    [Parameter(ParameterSetName = 'DirectLogonShellLauncher')]
    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]    
    [int]$LockScreenAfterSeconds,

    [Parameter(ParameterSetName = 'DirectLogonShellLauncher')]
    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]
    [switch]$SharedPC,

    [Parameter(ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]
    [switch]$ShowSettings,

    [Parameter(Mandatory, ParameterSetName = 'AutologonShellLauncher')]
    [Parameter(Mandatory, ParameterSetName = 'DirectLogonShellLauncher')]
    [switch]$WindowsAppShell,

    [Parameter(ParameterSetName = 'DirectLogonShellLauncher')]
    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]
    [ValidateSet('Lock', 'Logoff')]
    [string]$SmartCardRemovalAction,

    [version]$Version = '1.0.0'
)

If ($WindowsAppAutoLogoffConfig -eq 'ResetAppOnCloseOrIdle' -and $null -eq $WindowsAppAutoLogoffTimeInterval) {
    Throw "You must specify a value for 'WindowsAppAutoLogoffTimeInterval' when 'WindowsAppAutoLogoffConfig' = 'ResetAppOnCloseOrIdle'"
} 

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
$EventLog = 'Windows-App-Kiosk'
$EventSource = 'Configuration'
# Find LTSC OS (and Windows IoT Enterprise)
$OS = Get-WmiObject -Class Win32_OperatingSystem
# Detect Windows 11
If ($OS.Name -match 'LTSC') { $LTSC = $true }
# Source Directories and supporting files
$DirAppLocker = Join-Path -Path $Script:Dir -ChildPath "AppLocker"
$FileAppLockerClear = Join-Path -Path $DirAppLocker -ChildPath "ClearAppLockerPolicy.xml"
$DirApps = Join-Path -Path $Script:Dir -ChildPath 'Apps'
$DirAssignedAccess = Join-Path -Path $Script:Dir -ChildPath 'AssignedAccess'
$DirMultiAppSettings = Join-Path -Path $DirAssignedAccess -ChildPath 'MultiApp'
$DirProvisioningPackages = Join-Path -Path $Script:Dir -ChildPath 'ProvisioningPackages'
$DirShellLauncherSettings = Join-Path -Path $DirAssignedAccess -ChildPath 'ShellLauncher'
$DirGPO = Join-Path -Path $Script:Dir -ChildPath "GPOSettings"
$DirKiosk = Join-Path -Path $env:SystemDrive -ChildPath "KioskSettings"
$DirTools = Join-Path -Path $Script:Dir -ChildPath "Tools"
$DirUserLogos = Join-Path -Path $Script:Dir -ChildPath "UserLogos"
$DirFunctions = Join-Path -Path $Script:Dir -ChildPath "Scripts\Functions"
$DirSchedTasksScripts = Join-Path -Path $Script:Dir -ChildPath "Scripts\ScheduledTasks"
$FileKeyboardFilterConfig = Join-Path -Path $DirSchedTasksScripts -ChildPath "Set-KeyboardFilterConfiguration.ps1"
    
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
Write-Output "Pausing for 5 seconds to ensure event log is ready..."
Start-Sleep -Seconds 5

$message = @"
Starting Windows App Kiosk Configuration Script
Script Full Name: $($Script:FullName)
Parameters:
    $($PSBoundParameters | Out-String)
Running on: $($OS.Caption) version $($OS.Version)
"@
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 1 -Message $message

If (Get-PendingReboot) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Warning -EventId 0 -Message "There is a reboot pending. This application cannot be installed when a reboot is pending.`nRebooting the computer in 15 seconds."
    Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r /t 15' -NoNewWindow
    Exit
}

# Copy lgpo to system32 for future use.
Copy-Item -Path "$DirTools\lgpo.exe" -Destination "$env:SystemRoot\System32" -Force

#endregion Initialization

#region Remove Previous Versions

# Run Removal Script first in the event that a previous version is installed or in the event of a failed installation.
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 3 -Message 'Running removal script in case of previous installs or failures.'
& "$Script:Dir\Remove-KioskSettings.ps1" -Reinstall

#endregion Previous Version Removal

#region Remove Apps

# Remove Built-in Windows 11 Apps on non LTSC builds of Windows
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

#region Install AVD Client

If ($InstallWindowsApp) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 31 -Message "Running Script to install or update the Windows App."
    & "$DirApps\WindowsApp\Deploy-WindowsApp.ps1"
}

#endregion Install AVD Client

#region KioskSettings Directory

#Create the KioskSettings Directory
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 40 -Message "Creating KioskSettings Directory at root of system drive."
If (-not (Test-Path $DirKiosk)) {
    New-Item -Path $DirKiosk -ItemType Directory -Force | Out-Null
}

# Setting ACLs on the Kiosk Settings directory to prevent Non-Administrators from changing files. Defense in Depth.
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 41 -Message "Configuring Kiosk Directory ACLs"
$AdminsSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$Group = $AdminsSID.Translate([System.Security.Principal.NTAccount])
$ACL = Get-ACL $DirKiosk
$ACL.SetOwner($Group)
Set-ACL -Path $DirKiosk -AclObject $ACL
Update-ACL -Path $DirKiosk -Identity 'S-1-5-32-544' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'S-1-5-32-545' -FileSystemRights 'ReadAndExecute' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'S-1-5-18' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACLInheritance -Path $DirKiosk -DisableInheritance $true -PreserveInheritedACEs $false

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

If (!$WindowsAppShell) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 44 -Message "Adding Provisioning Package to hide Start Menu Elements"
    $ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'HideStartMenuElements.ppkg'
}

New-Item -Path "$DirKiosk\ProvisioningPackages" -ItemType Directory -Force | Out-Null
ForEach ($Package in $ProvisioningPackages) {
    Copy-Item -Path $Package -Destination "$DirKiosk\ProvisioningPackages" -Force | Out-Null
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventID 46 -Message "Installing $($Package)."
    Install-ProvisioningPackage -PackagePath $Package -ForceInstall -QuietInstall
}

#endregion Provisioning Packages

#region User Logos
if ($AutoLogonKiosk) {
    $null = cmd /c lgpo.exe /t "$DirGPO\AutoLogon-UserLogos.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 55 -Message "Configured User Logos to use default via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 56 -Message "Backing up current User Logo files to '$DirKiosk\UserLogos'."
    Copy-Item -Path "$env:ProgramData\Microsoft\User Account Pictures" -Destination "$DirKiosk\UserLogos" -Force
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 57 -Message "Copying User Logo files to '$env:ProgramData\Microsoft\User Account Pictures'."
    Get-ChildItem -Path $DirUserLogos | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force
}
#endregion User Logos

#region Local GPO Settings

if ($WindowsAppShell) {
    $null = cmd /c lgpo.exe /t "$DirGPO\ShellLauncher-DisableTaskMgr.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 60 -Message "Disabled Task Manager via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
}
Else {
    # Hide Windows Security notification area control
    $null = cmd /c lgpo.exe /t "$DirGPO\MultiApp-HideWindowsSecurityControl.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 60 -Message "Hide Windows Security notification area control via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
}

If ($ShowSettings) {
    $null = cmd /c lgpo.exe /t "$DirGPO\MultiApp-ShowSettings.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 63 -Message "Restricted Settings App and Control Panel to allow only Display Settings for kiosk user via Non-Administrators Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
}

If ($AutoLogonKiosk) {
    # Disable Password requirement for screen saver lock and wake from sleep.
    $null = cmd /c lgpo.exe /t "$DirGPO\AutoLogon-DisablePasswordForUnlock.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 80 -Message "Disabled password requirement for screen saver lock and wake from sleep via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    $null = cmd /c lgpo.exe /t "$DirGPO\AutoLogon-HideLockLogoff.txt" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 81 -Message "Removed logoff, change password, lock workstation, and fast user switching entry points. `nlgpo.exe Exit Code: [$LastExitCode]"
}
Else {
    If ($SmartCardRemovalAction) {
        # Ensure Smart Card Removal Policy service is running and set to automatic
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 82 -Message "Configuring Smart Card Removal Policy service."
        $SCPolicyService = Get-Service -Name 'SCPolicySvc' -ErrorAction Stop
        If ($SCPolicyService.StartType -ne 'Automatic') {
            Set-Service -Name 'SCPolicySvc' -StartupType Automatic
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 82 -Message "Smart Card Removal Policy service startup type set to Automatic."
        }           
    }
    If ($SmartCardRemovalAction -eq 'Lock') {
        $null = cmd /c lgpo /s "$DirGPO\SmartCardLockWorkstation.inf" '2>&1'
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Lock Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    }
    ElseIf ($SmartCardRemovalAction -eq 'Logoff') {
        $null = cmd /c lgpo /s "$DirGPO\SmartCardLogOffWorkstation.inf" '2>&1'
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Force Logoff Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    }
    If ($LockScreenAfterSeconds) {
        # Will lock the system via the inactivity timeout built-in policy which locks the screen after inactivity.
        $sourceFile = Join-Path -Path $DirGPO -ChildPath 'MachineInactivityTimeout.inf'
        $outFile = Join-Path -Path "$env:SystemRoot\SystemTemp" -ChildPath 'MachineInactivityTimeout.inf'
        (Get-Content -Path $SourceFile).Replace('<Seconds>', ($LockScreenAfterSeconds)) | Out-File $OutFile
        $null = cmd /c lgpo /s "$outFile" '2>&1'
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 85 -Message "Set 'Interactive logon: Machine inactivity limit' to '$LockScreenAfterSeconds seconds' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
        Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
    }
}

#endregion Local GPO Settings

#region Registry Edits

# Import registry keys file
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 90 -Message "Setting Registry Keys."
$RegValues = @()

$RegValues += [PSCustomObject]@{
    Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'
    Name         = 'BlockAADWorkplaceJoin'
    PropertyType = 'DWord'
    Value        = 1
    Description  = 'Disable "Stay Signed in to all your apps" pop-up'
}

If ($OneDrivePresent) {
    # Remove OneDrive from starting for each user.
    $RegValues += [PSCustomObject]@{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        Name         = 'OneDriveSetup'
        PropertyType = 'String'
        Value        = ''
        Description  = 'Remove OneDriveSetup from starting for each user.'
    }
}

If (-not $WindowsAppShell) {
    $RegValues += [PSCustomObject]@{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Name         = 'StartShownOnUpgrade'
        PropertyType = 'DWord'
        Value        = 1
        Description  = 'Disable Start Menu from opening automatically'
    }
}

if (($AutoLogonKiosk -and $WindowsAppAutoLogoffConfig -ne 'Disabled') -or $SharedPC) {
    # Streamline the user experience by disabling First Run Experience
    # https://learn.microsoft.com/en-us/windows-app/windowsautologoff#skipfre
    $RegValues += [PSCustomObject]@{
        Path         = 'HKLM:\SOFTWARE\Microsoft\Windows365'
        Name         = 'SkipFRE'
        PropertyType = 'DWord'
        Value        = 1
        Description  = 'Disable First Run Experience in Windows App'
    }
}

If ($AutoLogonKiosk) {
    #Configure AutoLogoff for the Windows App
    #https://learn.microsoft.com/en-us/windows-app/windowsautologoff
    Switch ($WindowsAppAutoLogoffConfig) {
        'ResetAppOnCloseOnly' {
            $RegValues += [PSCustomObject]@{
                Path         = 'HKLM:\SOFTWARE\Microsoft\WindowsApp'
                Name         = 'AutoLogoffEnable'
                PropertyType = 'DWORD'
                Value        = 1
                Description  = 'Sign all users out of Windows App and reset app data when the user closes the app.'
            }
        }
        'ResetAppAfterConnection' {
            $RegValues += [PSCustomObject]@{
                Path         = 'HKLM:\SOFTWARE\Microsoft\WindowsApp'
                Name         = 'AutoLogoffOnSuccessfulConnect'
                PropertyType = 'DWord'
                Value        = 1
                Description  = 'Sign all users out of Windows App and reset app data when a successful connection to an Azure Virtual Desktop session host or Windows 365 Cloud PC is made.'
            }
        }
        'ResetAppOnCloseOrIdle' {
            $RegValues += [PSCustomObject]@{
                Path         = 'HKLM:\SOFTWARE\Microsoft\WindowsApp'
                Name         = 'AutoLogoffTimeInterval'
                PropertyType = 'DWord'
                Value        = $WindowsAppAutoLogoffTimeInterval
                Description  = 'Sign all users out of Windows App and reset app data when the operating system is idle for the specified time interval in minutes or the user closes the app.'
            }     
        }
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
    $PathHKLM = $Null
    #set values
    $Path = $Entry.Path
    $Name = $Entry.Name
    $PropertyType = $Entry.PropertyType
    $Value = $Entry.Value
    $Description = $Entry.Description
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 99 -Message "Processing Registry Value to '$Description'."

    If ($Path -like 'HKCU:*') {
        $PathHKLM = $Path.Replace("HKCU:\", "HKLM:\Default\")
    }
    Else {
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
    $null = cmd /c REG UNLOAD "HKLM\Default" '2>&1'
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 104 -Message "Reg.exe Exit Code: [$LastExitCode]"
}

#endregion Registry Edits

#region Assigned Access Configuration

Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Starting Assigned Access Configuration Section."
If ($WindowsAppShell) {
    If ($AutoLogonKiosk) {
        $ConfigFile = Join-Path -Path $DirShellLauncherSettings -ChildPath "WindowsApp_AutoLogon.xml"
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 114 -Message "Enabling Windows App Shell Launcher with Autologon via WMI MDM bridge."
    }
    Else {
        $ConfigFile = Join-Path -Path $DirShellLauncherSettings -ChildPath "WindowsApp.xml"
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 114 -Message "Enabling Windows App Shell Launcher via WMI MDM bridge."
    }
    $DestFile = Join-Path -Path $DirKiosk -ChildPath "AssignedAccessShellLauncher.xml"
    Copy-Item -Path $ConfigFile -Destination $DestFile -Force
    Set-AssignedAccessShellLauncher -FilePath $DestFile
    If (Get-AssignedAccessShellLauncher) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 115 -Message "Shell Launcher configuration successfully applied."
    }
    Else {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Error -EventId 116 -Message "Shell Launcher configuration failed. Computer should be restarted first."
        Exit 1618
    }
}
Else {
    If ($AutoLogonKiosk) {
        If ($ShowSettings) {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App with Settings and Autologon."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_Settings_AutoLogon.xml"
        }
        Else {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App and Autologon."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_AutoLogon.xml"
        }
    }
    Else {
        If ($ShowSettings) {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App and Settings."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_Settings.xml"
        }
        Else {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp.xml"
        }
    }  
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 114 -Message "Configuration File = $ConfigFile"
    $DestFile = Join-Path $DirKiosk -ChildPath 'AssignedAccessConfiguration.xml'
    Copy-Item -Path $ConfigFile -Destination $DestFile -Force
    Set-AssignedAccessConfiguration -FilePath $DestFile
    If (Get-AssignedAccessConfiguration) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 115 -Message "Assigned Access configuration successfully applied."
    }
    Else {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Error -EventId 116 -Message "Assigned Access configuration failed. Computer should be restarted first."
        Exit 1618        
    }  
}

#endregion Assigned Access Launcher

#region AppLocker Configuration

If ($WindowsAppShell) {
    Write-Log -EntryType Information -EventId 120 -Message "Applying AppLocker Policy to disable Explorer, Edge, and Search for the Kiosk User."
    # If there is an existing applocker policy, back it up and store its XML for restore.
    # Else, copy a blank policy to the restore location.
    # Then apply the new AppLocker Policy
    $FileAppLockerKiosk = Join-Path -Path $DirAppLocker -ChildPath "ShellLauncher.xml"

    [xml]$Policy = Get-ApplockerPolicy -Local -XML
    If ($Policy.AppLockerPolicy.RuleCollection) {
        Get-ApplockerPolicy -Local -XML | out-file "$DirKiosk\ApplockerPolicy.xml" -force
    }
    Else {
        Copy-Item -Path $FileAppLockerClear -Destination "$DirKiosk\ApplockerPolicy.xml" -Force
    }
    Set-AppLockerPolicy -XmlPolicy $FileAppLockerKiosk
    Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 121 -Message "Enabling and Starting Application Identity Service"
    Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
}

#endregion AppLocker Configuration

#region Keyboard Filter

if ($WindowsAppShell) {
    New-Item -Path (Join-Path -Path $DirKiosk -ChildPath 'ScheduledTasksScripts') -ItemType Directory -Force | Out-Null
    $SchedTasksScriptsDir = Join-Path -Path $DirKiosk -ChildPath 'ScheduledTasksScripts'
    Copy-Item -Path $FileKeyboardFilterConfig -Destination $SchedTasksScriptsDir -Force
    $TaskScriptName = 'Set-KeyboardFilterConfiguration.ps1'
    $TaskScriptFullName = Join-Path -Path $SchedTasksScriptsDir -ChildPath $TaskScriptName
    Write-Log -EntryType Information -EventID 125 -Message "Enabling Keyboard filter."
    Enable-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter -All -NoRestart
    # Configure Keyboard Filter after reboot
    $TaskName = "(AVD Client) - Configure Keyboard Filter"
    Write-Log -EntryType Information -EventId 126 -Message "Creating Scheduled Task: '$TaskName'."
    $TaskScriptEventSource = 'Keyboard Filter Configuration'
    $TaskDescription = "Configures the Keyboard Filter"
    New-EventLog -LogName $EventLog -Source $TaskScriptEventSource -ErrorAction SilentlyContinue     
    $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
    $TaskScriptArgs = "-TaskName `"$TaskName`" -EventLog `"$EventLog`" -EventSource `"$TaskScriptEventSource`""
    $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-executionpolicy bypass -file $TaskScriptFullName $TaskScriptArgs"
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $TaskAction -Settings $TaskSettings -Principal $TaskPrincipal -Trigger $TaskTrigger
    If (Get-ScheduledTask | Where-Object { $_.TaskName -eq "$TaskName" }) {
        Write-Log -EntryType Information -EventId 119 -Message "Scheduled Task created successfully."
    }
    Else {
        Write-Log -EntryType Error -EventId 120 -Message "Scheduled Task not created."
        Exit 1618
    }
}

#endregion Keyboard Filter

Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 150 -Message "Updating Group Policy"
$GPUpdate = Start-Process -FilePath 'GPUpdate' -ArgumentList '/force' -Wait -PassThru
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventID 151 -Message "GPUpdate Exit Code: [$($GPUpdate.ExitCode)]"
$null = cmd /c reg add 'HKLM\Software\Kiosk' /v Version /d "$($Version.ToString())" /t REG_SZ /f
Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 199 -Message "Ending Kiosk Mode Configuration version '$($Version.ToString())' with Exit Code: 3010"
Exit 3010
