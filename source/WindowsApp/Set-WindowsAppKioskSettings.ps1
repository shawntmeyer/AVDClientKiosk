<# 
.SYNOPSIS
    This script creates a custom Remote Desktop client for Windows (AVD Client) kiosk configuration designed to only allow the use of the client.
    It uses a combination of Applocker policies, multi-local group policy settings, Shell Launcher configuration, provisioning packages, and
    registry edits to complete the configuration. There are basically four major options for configuration:

    * Remote Desktop client shell
    * Remote Desktop client shell with autologon
    * Custom Explorer shell (Windows 10) or Multi-App Kiosk Shell (Windows 11)
    * Custom Explorer shell (Windows 10) or Multi-App Kiosk Shell (Windows 11), both with autologon

    These options are controlled by the combination of the two switch parameters - SingleAppKiosk and Autologon.
    
    When the SingleAppKiosk switch parameter is not used, then you can utilize the -ShowDisplaySettings switch parameter to allow access to the Display Settings page.
    
    Additionally, you can choose to

    * Install the latest Remote Desktop client for Windows and Visual C++ Redistributables directly from the web.
    * Apply the latest applicable Security Technical Implementation Guides (STIG) group policy settings into the local group policy object via the
      local group policy object tool. This also applies several delta settings to maintain operability as a kiosk.
    * Monitor for FIDO Passkey device removals and perform the same actions as smart cards such as local computer lock or Remote Desktop
      client reset.

.DESCRIPTION 
    This script completes a series of configuration tasks based on the parameters chosen. These tasks can include:

    * Applocker policy application to block Internet Explorer, Edge, Wordpad, and Notepad
    * Provisioning packages to remove pinned items from the Start Menu for the custom explorer shell option with Windows 10.
    * Provisioning packages to enable SharedPC mode.
    * Multi-Local Group Policy configuration to limit interface elements.
    * Built-in application removal.
    * Shell Launcher configuration for the SingleAppKiosk and Windows 10 Autologon scenarios
    * Multi-App Kiosk configuration for Windows 11 when the SingleAppKiosk switch parameter is not used.
    * Remote Desktop client for Windows install (If selected)
    * STIG application (If selected)
    * Start layout modification for the custom explorer shell options
    * Custom Azure Virtual Desktop client shortcuts that launches the Remote Desktop client for Windows
      via a script to enable WMI Event subscription.

.NOTES 
    The script will automatically remove older configurations by running 'Remove-KioskSettings.ps1' during the install process.    

.COMPONENT 
    No PowerShell modules required.

.LINK 


.PARAMETER AutoLogon
This switch parameter determines If autologon is enabled through the Shell Launcher configuration. The Shell Launcher feature will automatically
create a new user - 'KioskUser0' - which will not have a password and be configured to automatically logon when Windows starts.

.PARAMETER AutoLogonConfig
This string parameter determines the autologon configuration for the Windows App when the AutoLogon switch parameter is used. The possible values are:
* Disabled - Disables automatic sign-out and app data reset for the Windows App. (Not RECOMMENDED for Kiosk scenarios)
* ResetAppOnCloseOnly - Sign all users out of Windows App and reset app data when the user closes the app.
* ResetAppAfterConnection - Sign all users out of Windows App and reset app data when a successful connection to an Azure Virtual Desktop session host or Windows 365 Cloud PC is made.
* ResetAppOnCloseOrIdle - Sign all users out of Windows App and reset app data when the operating system is idle for the specified time interval in minutes or the user closes the app.

.PARAMETER SingleAppKiosk
This switch parameter determines whether the Windows Shell is replaced by the Remote Desktop client for Windows or remains the default 'explorer.exe'.
When the default 'explorer' shell is used additional local group policy settings and provisioning packages are applied to lock down the shell.

.PARAMETER InstallWindowsApp
This switch parameter determines If the latest Remote Desktop client for Windows is automatically downloaded from the Internet and installed
on the system prior to configuration.

.PARAMETER SharedPC
This switch parameter determines If the computer is setup as a shared PC. The account management process is enabled and all user profiles are automatically
deleted on logoff.

.PARAMETER ShowSettings
This switch parameter determines If the Settings App appears on the start menu. The settings app and control panel are restricted to the applets/pages specified in the nonadmins-ShowSettings.txt file. If this value is not set,
then the Settings app and Control Panel are not displayed or accessible.

.PARAMETER IdleTimeOutInMinutes
This integer value determines the number of minutes in the that system will wait before performing the action specified in the IdleTimeoutAction parameter.

.PARAMETER SmartCardRemovalAction   
This string parameter determines what occurs when the smart card that was used to authenticate to the operating system is removed from the system. The possible values are 'Lock' or 'Logoff'.
When AutoLogon is true, this parameter cannot be used.

.PARAMETER Version
This version parameter allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager or Microsoft Endpoint Configuration Manager by querying the value of the registry value: HKLM\Software\Kiosk\version.

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory, ParameterSetName = 'AutologonSingleAppKiosk')]
    [Parameter(Mandatory, ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [switch]$AutoLogon,

    [Parameter(Mandatory, ParameterSetName = 'AutologonSingleAppKiosk')]
    [Parameter(Mandatory, ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [ValidateSet('Disabled', 'ResetAppOnCloseOnly', 'ResetAppAfterConnection', 'ResetAppOnCloseOrIdle')]
    [string]$AutoLogonConfig,

    [int]$IdleTimeoutInMinutes = 15,

    [switch]$InstallWindowsApp,

    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]
    [Parameter(ParameterSetName = 'DirectLogonSingleAppKiosk')]
    [switch]$LockScreenOnIdleTimeout,

    [Parameter(ParameterSetName = 'DirectLogonSingleAppKiosk')]
    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]
    [switch]$SharedPC,

    [Parameter(ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]
    [switch]$ShowSettings,

    [Parameter(Mandatory, ParameterSetName = 'AutologonSingleAppKiosk')]
    [Parameter(Mandatory, ParameterSetName = 'DirectLogonSingleAppKiosk')]
    [switch]$SingleAppKiosk,

    [Parameter(ParameterSetName = 'DirectLogonSingleAppKiosk')]
    [Parameter(ParameterSetName = 'DirectLogonMultiAppKiosk')]
    [ValidateSet('Lock', 'Logoff')]
    [string]$SmartCardRemovalAction,

    [version]$Version = '1.0.0'
)

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
$EventLog = 'Windows App Kiosk'
$EventSource = 'Configuration Script'
# Find LTSC OS (and Windows IoT Enterprise)
$OS = Get-WmiObject -Class Win32_OperatingSystem
# Detect Windows 11
If ($OS.Name -match 'LTSC') { $LTSC = $true }
# Source Directories and supporting files
$DirApps = Join-Path -Path $Script:Dir -ChildPath 'Apps'
$DirAssignedAccess = Join-Path -Path $Script:Dir -ChildPath 'AssignedAccess'
$DirMultiAppSettings = Join-Path -Path $DirAssignedAccess -ChildPath 'MultiApp'
$DirProvisioningPackages = Join-Path -Path $Script:Dir -ChildPath 'ProvisioningPackages'
$DirSingleAppSettings = Join-Path -Path $DirAssignedAccess -ChildPath 'SingleApp'
$DirGPO = Join-Path -Path $Script:Dir -ChildPath "GPOSettings"
$DirKiosk = Join-Path -Path $env:SystemDrive -ChildPath "KioskSettings"
$DirTools = Join-Path -Path $Script:Dir -ChildPath "Tools"
$DirUserLogos = Join-Path -Path $Script:Dir -ChildPath "UserLogos"
$DirFunctions = Join-Path -Path $Script:Dir -ChildPath "Scripts\Functions"
    
# Set default exit code to 0
$ScriptExitCode = 0

#region Load Functions

$Functions = Get-ChildItem -Path $DirFunctions -Filter '*.ps1'
ForEach ($Function in $Functions) {
    . "$($Function.FullName)"
}

#endregion Functions

#region Initialization

New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction SilentlyContinue

Write-Log -EntryType Information -EventId 1 -Message "Executing '$Script:FullName'."
Write-Log -EntryType Information -EventId 2 -Message "Running on $($OS.Caption) version $($OS.Version)."

If (Get-PendingReboot) {
    Write-Log -EntryType Error -EventId 0 -Message "There is a reboot pending. This application cannot be installed when a reboot is pending.`nRebooting the computer in 15 seconds."
    Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r /t 15'
    Exit 3010
}

# Copy lgpo to system32 for future use.
Copy-Item -Path "$DirTools\lgpo.exe" -Destination "$env:SystemRoot\System32" -Force

#endregion Inistiialization

#region Remove Previous Versions

# Run Removal Script first in the event that a previous version is installed or in the event of a failed installation.
Write-Log -EntryType Information -EventId 3 -Message 'Running removal script in case of previous installs or failures.'
& "$Script:Dir\Remove-KioskSettings.ps1"

#endregion Previous Version Removal

#region Remove Apps

# Remove Built-in Windows 11 Apps on non LTSC builds of Windows
If (-not $LTSC) {
    Write-Log -EntryType Information -EventId 25 -Message "Starting Remove Apps Script."
    Remove-BuildInApps
}
# Remove OneDrive
If (Test-Path -Path "$env:SystemRoot\Syswow64\onedrivesetup.exe") {
    Write-Log -EntryType Information -EventId 26 -Message "Removing Per-User installation of OneDrive."
    Start-Process -FilePath "$env:SystemRoot\Syswow64\onedrivesetup.exe" -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
    $OneDrivePresent = $true
}
ElseIf (Test-Path -Path "$env:ProgramFiles\Microsoft OneDrive") {
    Write-Log -EntryType Information -EventId 26 -Message "Removing Per-Machine Installation of OneDrive."
    $OneDriveSetup = Get-ChildItem -Path "$env:ProgramFiles\Microsoft OneDrive" -Filter 'onedrivesetup.exe' -Recurse
    If ($OneDriveSetup) {
        Start-Process -FilePath $OneDriveSetup[0].FullName -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
        $OneDrivePresent = $true
    }
}

#endregion Remove Apps

#region Install AVD Client

If ($InstallWindowsApp) {
    Write-Log -EntryType Information -EventId 31 -Message "Running Script to install or update the Windows App."
    & "$DirApps\WindowsApp\Deploy-WindowsApp.ps1"
}

#endregion Install AVD Client

#region KioskSettings Directory

#Create the KioskSettings Directory
Write-Log -EntryType Information -EventId 40 -Message "Creating KioskSettings Directory at root of system drive."
If (-not (Test-Path $DirKiosk)) {
    New-Item -Path $DirKiosk -ItemType Directory -Force | Out-Null
}

# Setting ACLs on the Kiosk Settings directory to prevent Non-Administrators from changing files. Defense in Depth.
Write-Log -EntryType Information -EventId 41 -Message "Configuring Kiosk Directory ACLs"
$Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
$ACL = Get-ACL $DirKiosk
$ACL.SetOwner($Group)
Set-ACL -Path $DirKiosk -AclObject $ACL
Update-ACL -Path $DirKiosk -Identity 'BuiltIn\Administrators' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'BuiltIn\Users' -FileSystemRights 'ReadAndExecute' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'System' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACLInheritance -Path $DirKiosk -DisableInheritance $true -PreserveInheritedACEs $false

#endregion KioskSettings Directory

#region Provisioning Packages

$ProvisioningPackages = @()

Write-Log -EntryType Information -EventId 44 -Message "Adding Provisioning Package to disable Windows Spotlight"
$ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'DisableWindowsSpotlight.ppkg'

Write-Log -EntryType Information -EventId 44 -Message "Adding Provisioning Package to disable first sign-in animation"
$ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'DisableFirstLogonAnimation.ppkg'

If ($SharedPC) {
    Write-Log -EntryType Information -EventId 44 -Message "Adding Provisioning Package to enable SharedPC mode"
    $ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'SharedPC.ppkg'
}

If (!$SingleAppKiosk) {
    Write-Log -EntryType Information -EventId 44 -Message "Adding Provisioning Package to hide Start Menu Elements"
    $ProvisioningPackages += Join-Path -Path $DirProvisioningPackages -ChildPath 'HideStartMenuElements.ppkg'
}

New-Item -Path "$DirKiosk\ProvisioningPackages" -ItemType Directory -Force | Out-Null
ForEach ($Package in $ProvisioningPackages) {
    Copy-Item -Path $Package -Destination "$DirKiosk\ProvisioningPackages" -Force
    Write-Log -EntryType Information -EventID 46 -Message "Installing $($Package)."
    Install-ProvisioningPackage -PackagePath $Package -ForceInstall -QuietInstall
}

#endregion Provisioning Packages

#region User Logos
if ($AutoLogon) {
    $null = cmd /c lgpo.exe /t "$DirGPO\computer-userlogos.txt" '2>&1'
    Write-Log -EntryType Information -EventId 55 -Message "Configured User Logos to use default via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    Write-Log -EntryType Information -EventId 56 -Message "Backing up current User Logo files to '$DirKiosk\UserLogos'."
    Copy-Item -Path "$env:ProgramData\Microsoft\User Account Pictures" -Destination "$DirKiosk\UserLogos" -Force
    Write-Log -EntryType Information -EventId 57 -Message "Copying User Logo files to '$env:ProgramData\Microsoft\User Account Pictures'."
    Get-ChildItem -Path $DirUserLogos | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force
}
#endregion User Logos

#region Local GPO Settings

# Apply Non-Admin GPO settings
If ($ShowSettings) {
    $null = cmd /c lgpo.exe /t "$DirGPO\nonadmins-ShowSettings.txt" '2>&1'
    Write-Log -EntryType Information -EventId 63 -Message "Restricted Settings App and Control Panel to allow only Display Settings for kiosk user via Non-Administrators Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
}

If ($AutoLogon) {
    # Disable Password requirement for screen saver lock and wake from sleep.
    $null = cmd /c lgpo.exe /t "$DirGPO\disablePasswordForUnlock.txt" '2>&1'
    Write-Log -EntryType Information -EventId 80 -Message "Disabled password requirement for screen saver lock and wake from sleep via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    $null = cmd /c lgpo.exe /t "$DirGPO\nonadmins-autologon.txt" '2>&1'
    Write-Log -EntryType Information -EventId 81 -Message "Removed logoff, change password, lock workstation, and fast user switching entry points. `nlgpo.exe Exit Code: [$LastExitCode]"
}
Else {
    If ($SmartCardRemovalAction) {
        If ($SmartCardRemovalAction -eq 'Lock') {
            $null = cmd /c lgpo /s "$DirGPO\SmartCardLockWorkstation.inf" '2>&1'
            Write-Log -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Lock Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
        }
        ElseIf ($SmartCardRemovalAction -eq 'Logoff') {
            $null = cmd /c lgpo /s "$DirGPO\SmartCardLogOffWorkstation.inf" '2>&1'
            Write-Log -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Force Logoff Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
        }
    }
    If ($LockScreenOnIdleTimeout) {
        # Will lock the system via the inactivity timeout built-in policy which locks the screen after inactivity.
        $sourceFile = Join-Path -Path $DirGPO -ChildPath 'MachineInactivityTimeout.inf'
        $outFile = Join-Path -Path "$env:SystemRoot\SystemTemp" -ChildPath 'MachineInactivityTimeout.inf'
        (Get-Content -Path $SourceFile).Replace('<Seconds>', ($IdleTimeoutInMinutes * 60)) | Out-File $outFile
        $null = cmd /c lgpo /s "$outFile" '2>&1'
        Write-Log -EntryType Information -EventId 85 -Message "Set 'Interactive logon: Machine inactivity limit' to '$($IdleTimeout * 60) seconds' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
        Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
    }
}

#endregion Local GPO Settings

#region Registry Edits

# Import registry keys file
Write-Log -EntryType Information -EventId 90 -Message "Setting Registry Keys."
$RegKeys = @()

$RegKeys += [PSCustomObject]@{
    Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'
    Name         = 'BlockAADWorkplaceJoin'
    PropertyType = 'DWord'
    Value        = 1
    Description  = "Disable 'Stay Signed in to all your apps' pop-up"
}

If ($OneDrivePresent) {
    # Remove OneDrive from starting for each user.
    $RegKeys += [PSCustomObject]@{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        Name         = 'OneDriveSetup'
        PropertyType = 'String'
        Value        = ''
        Description  = 'Remove OneDriveSetup from starting for each user.'
    }
}

if (($AutoLogon -and $AutoLogonConfig -ne 'Disabled') -or $SharedPC) {
    # Streamline the user experience by disabling First Run Experience
    # https://learn.microsoft.com/en-us/windows-app/windowsautologoff#skipfre
    $RegKeys += [PSCustomObject]@{
        Path         = 'HKLM:\SOFTWARE\Microsoft\WindowsApp'
        Name         = 'SkipFRE'
        PropertyType = 'DWord'
        Value        = 1
        Description  = 'Disable First Fun Experience in Windows App'
    }
}

If ($AutoLogon) {
    #Configure AutoLogoff for the Windows App
    #https://learn.microsoft.com/en-us/windows-app/windowsautologoff
    Switch ($AutoLogonConfig) {
        'ResetAppOnCloseOnly' {
            $RegKeys += [PSCustomObject]@{
                Path         = 'HKLM:\SOFTWARE\Microsoft\WindowsApp'
                Name         = 'AutoLogoffEnable'
                PropertyType = 'DWORD'
                Value        = 1
                Description  = 'Sign all users out of Windows App and reset app data when the user closes the app.'
            }
        }
        'ResetAppAfterConnection' {
            $RegKeys += [PSCustomObject]@{
                Path         = 'HKLM:\SOFTWARE\Microsoft\WindowsApp'
                Name         = 'AutoLogoffOnSuccessfulConnect'
                PropertyType = 'DWord'
                Value        = 1
                Description  = 'Sign all users out of Windows App and reset app data when a successful connection to an Azure Virtual Desktop session host or Windows 365 Cloud PC is made.'
            }
        }
        'ResetAppOnCloseOrIdle' {
            $RegKeys += [PSCustomObject]@{
                Path         = 'HKLM:\SOFTWARE\Microsoft\WindowsApp'
                Name         = 'AutoLogoffTimeInterval'
                PropertyType = 'DWord'
                Value        = $IdleTimeoutInMinutes
                Description  = 'Sign all users out of Windows App and reset app data when the operating system is idle for the specified time interval in minutes or the user closes the app.'
            }     
        }
    }
}

# create the reg key restore file if it doesn't exist, else load it to compare for appending new rows.
Write-Log -EntryType Information -EventId 97 -Message "Creating a Registry key restore file for Kiosk Mode uninstall."
$FileRestore = "$DirKiosk\RegKeyRestore.csv"
New-Item -Path $FileRestore -ItemType File -Force | Out-Null
Add-Content -Path $FileRestore -Value 'Path,Name,PropertyType,Value,Description'

# Loop through the registry key file and perform actions.
ForEach ($Entry in $RegKeys) {
    #reset from previous values
    $Path = $null
    $Name = $null
    $PropertyType = $null
    $Value = $null
    $Description = $Null
    #set values
    $Path = $Entry.Path
    $Name = $Entry.Name
    $PropertyType = $Entry.PropertyType
    $Value = $Entry.Value
    $Description = $Entry.Description
    Write-Log -EntryType Information -EventId 99 -Message "Processing Registry Value to '$Description'."

    If ($Path -like 'HKCU:\*') {
        $Path = $Path.Replace("HKCU:\", "HKLM:\Default\")
        If (-not (Test-Path -Path 'HKLM:\Default')) {
            Write-Log -EntryType Information -EventId 94 -Message "Loading Default User Hive Registry Keys via Reg.exe."
            $null = cmd /c REG LOAD "HKLM\Default" "$env:SystemDrive\Users\default\ntuser.dat" '2>&1'
            Write-Log -EntryType Information -EventId 95 -Message "Loaded Default User Hive Registry Keys via Reg.exe.`nReg.exe Exit Code: [$LastExitCode]"
        }
    }
    $CurrentRegValue = $null
    If (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
        $CurrentRegValue = Get-ItemPropertyValue -Path $Path -Name $Name
        Add-Content -Path $FileRestore -Value "$Path,$Name,$PropertyType,$CurrentRegValue"
    }
    Else {
        Add-Content -Path $FileRestore -Value "$Path,$Name,,"
    }

    If ($Value -ne '' -and $null -ne $Value) {
        # This is a set action
        Set-RegistryValue -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value       
        Write-Log -EntryType Information -EventId 100 -Message "Setting '$PropertyType' Value '$Name' with Value '$Value' to '$Path'"
    }
    Elseif ($CurrentRegValue) {     
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        Write-Log -EntryType Information -EventId 102 -Message "Deleted Value '$Name' from '$Path'."
    }               
}    

If (Test-Path -Path 'HKLM:\Default') {
    Write-Log -EntryType Information -EventId 103 -Message "Unloading Default User Hive Registry Keys via Reg.exe."
    $null = cmd /c REG UNLOAD "HKLM\Default" '2>&1'
    Write-Log -EntryType Information -EventId 104 -Message "Reg.exe Exit Code: [$LastExitCode]"
    If ($LastExitCode -ne 0) {
        # sometimes the registry doesn't unload properly so we have to perform powershell garbage collection first.
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        Start-Sleep -Seconds 5
        $null = cmd /c REG UNLOAD "HKLM\Default" '2>&1'
        If ($LastExitCode -eq 0) {
            Write-Log -EntryType Information -EventId 106 -Message "Hive unloaded successfully."
        }
        Else {
            Write-Log -EntryType Error -EventId 107 -Message "Default User hive unloaded with exit code [$LastExitCode]."
        }
    }
}

#endregion Registry Edits

#region Shell Launcher Configuration

Write-Log -EntryType Information -EventId 113 -Message "Starting Assigned Access Configuration Section."
If ($SingleAppKiosk) {
    If ($AutoLogon) {
        $ConfigFile = Join-Path -Path $DirSingleAppSettings -ChildPath "WindowsApp_AutoLogon.xml"
        Write-Log -EntryType Information -EventId 114 -Message "Enabling Single App Kiosk Windows App with Autologon via WMI MDM bridge."
    }
    Else {
        $ConfigFile = Join-Path -Path $DirSingleAppSettings -ChildPath "WindowsApp.xml"
        Write-Log -EntryType Information -EventId 114 -Message "Enabling Single App Kiosk Windows App via WMI MDM bridge."
    }
}
Else {
    If ($AutoLogon) {
        If ($ShowSettings) {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App with Settings and Autologon."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_Settings_AutoLogon.xml"
        }
        Else {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App and Autologon."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_AutoLogon.xml"
        }
    }
    Else {
        If ($ShowSettings) {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App and Settings."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_Settings.xml"
        }
        Else {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App."
            $ConfigFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp.xml"
        }
    }    
}
Write-Log -EntryType Information -EventId 114 -Message "Configuration File = $ConfigFile"
$DestFile = Join-Path $DirKiosk -ChildPath 'AssignedAccessConfiguration.xml'
Copy-Item -Path $ConfigFile -Destination $DestFile -Force
Set-AssignedAccessConfiguration -FilePath $DestFile
If (Get-AssignedAccessConfiguration) {
    Write-Log -EntryType Information -EventId 115 -Message "Assigned Access configuration successfully applied."
}
Else {
    Write-Log -EntryType Error -EventId 116 -Message "Assigned Access configuration failed. Computer should be restarted first."
    Exit 1        
}

#endregion Assigned Access Launcher

#endregion Prevent Microsoft AAD Broker Timeout
If ($ScriptExitCode -eq 1618) {
    Write-Log -EntryType Error -EventId 135 -Message "At least one critical failure occurred. Exiting Script and restarting computer."
    Restart-Computer -Force
}
Else {
    $ScriptExitCode -eq 1641
}
    
Write-Log -EntryType Information -EventId 150 -Message "Updating Group Policy"
$GPUpdate = Start-Process -FilePath 'GPUpdate' -ArgumentList '/force' -Wait -PassThru
Write-Log -EntryType Information -EventID 151 -Message "GPUpdate Exit Code: [$($GPUpdate.ExitCode)]"
$null = cmd /c reg add 'HKLM\Software\Kiosk' /v Version /d "$($version.ToString())" /t REG_SZ /f
Write-Log -EntryType Information -EventId 199 -Message "Ending Kiosk Mode Configuration version '$($version.ToString())' with Exit Code: $ScriptExitCode"
Exit $ScriptExitCode
