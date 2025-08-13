<# 
.SYNOPSIS
    This script creates a custom Remote Desktop client for Windows (AVD Client) kiosk configuration designed to only allow the use of the client.
    It uses a combination of Applocker policies, multi-local group policy settings, Shell Launcher configuration, provisioning packages, and
    registry edits to complete the configuration. There are basically four major options for configuration:

    * Remote Desktop client shell
    * Remote Desktop client shell with autologon
    * Custom Explorer shell (Windows 10) or Multi-App Kiosk Shell (Windows 11)
    * Custom Explorer shell (Windows 10) or Multi-App Kiosk Shell (Windows 11), both with autologon

    These options are controlled by the combination of the two switch parameters - AVDClientShell and Autologon.
    
    When the AVDClientShell switch parameter is not used, then you can utilize the -ShowDisplaySettings switch parameter to allow access to the Display Settings page.
    
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
    * Shell Launcher configuration for the AVDClientShell and Windows 10 Autologon scenarios
    * Multi-App Kiosk configuration for Windows 11 when the AVDClientShell switch parameter is not used.
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
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-windows?tabs=subscribe
    https://learn.microsoft.com/en-us/azure/virtual-desktop/uri-scheme
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview
    https://learn.microsoft.com/en-us/windows/configuration/kiosk-shelllauncher
    https://public.cyber.mil/stigs/gpo/
 
.PARAMETER EnvironmentAVD
This value determines the Azure environment to which you are connecting. It ultimately determines the Url of the Remote Desktop Feed which
varies by environment by setting the $SubscribeUrl variable and replacing placeholders in several files during installation.
The list of Urls can be found at
https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-microsoft-store?source=recommendations#subscribe-to-a-workspace.

.PARAMETER InstallAVDClient
This switch parameter determines If the latest Remote Desktop client for Windows is automatically downloaded from the Internet and installed
on the system prior to configuration.

.PARAMETER SharedPC
This switch parameter determines If the computer is setup as a shared PC. The account management process is enabled and all user profiles are automatically
deleted on logoff.

.PARAMETER TimeOut
This integer value determines the number of seconds in the AutoLogon scenario with the Triggers value containing 'IdleTimeout' that the system will stay idle before resetting the client.

.PARAMETER Triggers
This string array value determines the trigger(s) that will cause the Trigger Action to be carried out.
When AutoLogon is true, you can choose any or all of the following: 'DeviceRemoval' and 'IdleTimeout'.
If this value is not set then the TriggerAction is not used.

.PARAMETER TriggerAction
This string parameter determines what occurs when the specified trigger is detected.

.PARAMETER SmartCard
This switch parameter determines if SmartCard removal will trigger the 'TriggerAction'. This value is only used when 'Triggers' contains 'DeviceRemoval'.

.PARAMETER Version
This version parameter allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager or Microsoft Endpoint Configuration Manager by querying the value of the registry value: HKLM\Software\Kiosk\version.

#>
[CmdletBinding()]
param (
    [ValidateSet('AzureCloud', 'AzureUSGovernment')]
    [string]$EnvironmentAVD = 'AzureUSGovernment',

    [switch]$CustomShell,

    [switch]$InstallAVDClient,

    [switch]$SharedPC = $true,

    [switch]$SmartCard = $true,

    [int]$Timeout = 900,

    [ValidateSet('DeviceRemoval', 'IdleTimeout')]
    [string[]]$Triggers = @('DeviceRemoval', 'IdleTimeout'),

    [ValidateSet('Lock', 'Logoff')]
    [string]$TriggerAction = 'Lock',

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
$EventLog = 'AVD Client Kiosk'
$EventSource = 'Configuration Script'
# Source Directories and supporting files
$DirMultiAppSettings = Join-Path -Path $Script:Dir -ChildPath 'MultiAppConfigs'
$DirProvisioningPackages = Join-Path -Path $Script:Dir -ChildPath "ProvisioningPackages"
$DirGPO = Join-Path -Path $Script:Dir -ChildPath "GPOSettings"
$DirKiosk = Join-Path -Path $env:SystemDrive -ChildPath "KioskSettings"
$DirRegKeys = Join-Path -Path $Script:Dir -ChildPath "RegistryKeys"
$DirTools = Join-Path -Path $Script:Dir -ChildPath "Tools"
$DirConfigurationScripts = Join-Path -Path $Script:Dir -ChildPath "Scripts\Configuration"
# Find LTSC OS (and Windows IoT Enterprise)
$OS = Get-WmiObject -Class Win32_OperatingSystem
If ($OS.Name -match 'LTSC') { $LTSC = $true }
# Set AVD feed subscription Url.
If ($EnvironmentAVD -eq 'AzureUSGovernment') {
    $SubscribeUrl = 'https://rdweb.wvd.azure.us'
}
Else {
    $SubscribeUrl = 'https://client.wvd.microsoft.com'
}
    
# Set default exit code to 0
$ScriptExitCode = 0

#region Functions

function Update-ACL {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $Path,
        [Parameter(Mandatory = $true)]
        $Identity,
        [Parameter(Mandatory = $true)]
        $FileSystemRights,
        $InheritanceFlags = 'ContainerInherit,ObjectInherit',
        $PropogationFlags = 'None',
        [Parameter(Mandatory)]
        [ValidateSet('Allow', 'Deny')]
        $Type
    )

    If (Test-Path $Path) {
        $NewAcl = Get-ACL -Path $Path
        $FileSystemAccessRuleArgumentList = $Identity, $FileSystemRights, $InheritanceFlags, $PropogationFlags, $type
        $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $FileSystemAccessRuleArgumentList
        $NewAcl.SetAccessRule($FileSystemAccessRule)
        Set-Acl -Path "$Path" -AclObject $NewAcl
    }
}

function Update-ACLInheritance {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $false,
            Position = 1)]
        [bool]$DisableInheritance = $false,

        [Parameter(Mandatory = $true,
            Position = 2)]
        [bool]$PreserveInheritedACEs = $true
    )

    If (Test-Path $Path) {
        $NewACL = Get-Acl -Path $Path
        $NewACL.SetAccessRuleProtection($DisableInheritance, $PreserveInheritedACEs)
        Set-ACL -Path $Path -AclObject $NewACL
    }

}

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
        'Information' { Write-Host "[INFO] $Message" -ForegroundColor Green }
        'Warning' { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[ERROR] $Message" -ForegroundColor Red }
    }
}

#endregion Functions

#region Initialization

New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction SilentlyContinue

Write-Log -EntryType Information -EventId 1 -Message "Executing '$Script:FullName'."
Write-Log -EntryType Information -EventId 2 -Message "Running on $($OS.Caption) version $($OS.Version)."

# Copy lgpo to system32 for future use.
Copy-Item -Path "$DirTools\lgpo.exe" -Destination "$env:SystemRoot\System32" -Force
#endregion Inistiialization

#region Remove Previous Versions

# Run Removal Script first in the event that a previous version is installed or in the event of a failed installation.
If (Get-ItemProperty -Path 'HKLM:\Software\Kiosk' -Name 'Version' -ErrorAction SilentlyContinue) {
    Write-Log -EntryType Information -EventId 4 -Message 'Previous version of Kiosk Mode detected. Removing previous version.'
    & "$Script:Dir\Remove-KioskSettings.ps1" -Reinstall
}

#endregion Previous Version Removal

#region Remove Apps

# Remove Built-in Windows 10 Apps on non LTSC builds of Windows
If (-not $LTSC) {
    Write-Log -EntryType Information -EventId 25 -Message "Starting Remove Apps Script."
    & "$DirConfigurationScripts\Remove-BuiltinApps.ps1"
}
# Remove OneDrive
If (Test-Path -Path "$env:SystemRoot\Syswow64\onedrivesetup.exe") {
    Write-Log -EntryType Information -EventId 26 -Message "Removing Per-User installation of OneDrive."
    Start-Process -FilePath "$env:SystemRoot\Syswow64\onedrivesetup.exe" -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
}
ElseIf (Test-Path -Path "$env:ProgramFiles\Microsoft OneDrive") {
    Write-Log -EntryType Information -EventId 26 -Message "Removing Per-Machine Installation of OneDrive."
    $OneDriveSetup = Get-ChildItem -Path "$env:ProgramFiles\Microsoft OneDrive" -Filter 'onedrivesetup.exe' -Recurse
    If ($OneDriveSetup) {
        Start-Process -FilePath $OneDriveSetup[0].FullName -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
    }
}

#endregion Remove Apps

#region Install AVD Client

If ($installAVDClient) {
    Write-Log -EntryType Information -EventID 30 -Message "Running Script to install or update Visual C++ Redistributables."
    & "$DirConfigurationScripts\Install-VisualC++Redistributables.ps1"
    Write-Log -EntryType Information -EventId 31 -Message "Running Script to install or update AVD Client."
    & "$DirConfigurationScripts\Install-AVDClient.ps1"
}

#endregion Install AVD Client

#region KioskSettings Directory

Write-Log -EntryType Information -EventId 40 -Message "Creating KioskSettings Directory at root of system drive."
If (-not (Test-Path $DirKiosk)) {
    New-Item -Path $DirKiosk -ItemType Directory -Force | Out-Null
}
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

#region Remote Desktop Shortcut

# Force launch in full screen mode
$ObjShell = New-Object -ComObject WScript.Shell
$DirShortcut = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
$LinkRemoteDesktop = "Remote Desktop.lnk"
$PathLinkRD = Join-Path $DirShortcut -ChildPath $LinkRemoteDesktop
$ShortcutPath = $PathLinkRD
$Shortcut = $ObjShell.CreateShortcut($ShortcutPath)
$Shortcut.WindowStyle = 3
$Shortcut.Save()

#endregion Remote Desktop Shortcut

#region Provisioning Packages

$ProvisioningPackages = @()
$ProvisioningPackages += (Get-ChildItem -Path $DirProvisioningPackages | Where-Object { $_.Name -like 'Disable*' }).FullName
$ProvisioningPackages += (Get-ChildItem -Path $DirProvisioningPackages | Where-Object { $_.Name -like 'Disallow*' }).FullName
$ProvisioningPackages += (Get-ChildItem -Path $DirProvisioningPackages | Where-Object { $_.Name -like 'HideHibernateAndSleep*' }).FullName
$ProvisioningPackages += (Get-ChildItem -Path $DirProvisioningPackages | Where-Object { $_.Name -like 'Start-HideRecommendedSection*' }).FullName
If ($SharedPC) {
    $ProvisioningPackages += (Get-ChildItem -Path $DirProvisioningPackages | Where-Object { $_.Name -like 'SharedPC*' }).FullName
}
New-Item -Path "$DirKiosk\ProvisioningPackages" -ItemType Directory -Force | Out-Null
ForEach ($Package in $ProvisioningPackages) {
    Copy-Item -Path $Package -Destination "$DirKiosk\ProvisioningPackages" -Force
    Write-Log -EntryType Information -EventID 46 -Message "Installing Provisioning Package: $(Split-Path -Path $Package -Leaf)."
    Install-ProvisioningPackage -PackagePath $Package -ForceInstall -QuietInstall | Out-Null
}

#endregion Provisioning Packages

#region Local GPO Settings

# Apply Non-Admin GPO settings

$null = cmd /c lgpo.exe /t "$DirGPO\nonadmins-RestrictSettings.txt" '2>&1'
Write-Log -EntryType Information -EventId 62 -Message "Restricted Settings App and Control Panel to allow only Display and Sound Settings for kiosk user via Non-Administrators Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
$null = cmd /c lgpo.exe /t "$DirGPO\nonadmins-edge.txt" '2>&1'
Write-Log -EntryType Information -EventId 63 -Message "Configured Microsoft Edge to restrict URLs to only those for VDI.`nlgpo.exe Exit Code: [$LastExitCode]"

# Configure Feed URL for all Users
$outfile = "$env:Temp\Users-AVDURL.txt"
$sourceFile = Join-Path -Path $DirGPO -ChildPath 'users-AutoSubscribe.txt'
(Get-Content -Path $sourceFile).Replace('<url>', $SubscribeUrl) | Out-File $outfile
$null = cmd /c lgpo.exe /t "$outfile" '2>&1'
Write-Log -EntryType Information -EventId 70 -Message "Configured AVD Feed URL for all users via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"

If ($Triggers -contains 'DeviceRemoval' -and $SmartCard) {
    If ($TriggerAction -eq 'Lock') {
        $null = cmd /c lgpo /s "$DirGPO\SmartCardLockWorkstation.inf" '2>&1'
        Write-Log -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Lock Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    }
    ElseIf ($TriggerAction -eq 'Logoff') {
        $null = cmd /c lgpo /s "$DirGPO\SmartCardLogOffWorkstation.inf" '2>&1'
        Write-Log -EntryType Information -EventId 84 -Message "Set 'Interactive logon: Smart Card Removal behavior' to 'Force Logoff Workstation' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
    }
}
If ($Triggers -contains 'IdleTimeout' -and $TriggerAction -eq 'Lock') {
    # Will lock the system via the inactivity timeout built-in policy which locks the screen after inactivity.
    $sourceFile = Join-Path -Path $DirGPO -ChildPath 'MachineInactivityTimeout.inf'
    $outFile = Join-Path -Path $env:Temp -ChildPath 'MachineInactivityTimeout.inf'
        (Get-Content -Path $SourceFile).Replace('900', $Timeout) | Out-File $outFile
    $null = cmd /c lgpo /s "$outFile" '2>&1'
    Write-Log -EntryType Information -EventId 85 -Message "Set 'Interactive logon: Machine inactivity limit' to '$Timeout seconds' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
}

#endregion Local GPO Settings

#region Registry Edits

# update the Default User Hive to Hide the search button and task view icons on the taskbar.
$null = cmd /c REG LOAD "HKLM\Default" "$env:SystemDrive\Users\default\ntuser.dat" '2>&1'
Write-Log -EntryType Information -EventId 95 -Message "Loaded Default User Hive Registry Keys via Reg.exe.`nReg.exe Exit Code: [$LastExitCode]"

# Import registry keys file
Write-Log -EntryType Information -EventId 96 -Message "Loading Registry Keys from CSV file for modification of default user hive."
$RegKeys = Import-Csv -Path (Join-Path $DirRegKeys -ChildPath 'RegKeys.csv')

# create the reg key restore file if it doesn't exist, else load it to compare for appending new rows.
Write-Log -EntryType Information -EventId 97 -Message "Creating a Registry key restore file for Kiosk Mode uninstall."
$FileRestore = "$DirKiosk\RegKeyRestore.csv"
New-Item -Path $FileRestore -ItemType File -Force | Out-Null
Add-Content -Path $FileRestore -Value 'Key,Value,Type,Data,Description'

# Loop through the registry key file and perform actions.
ForEach ($Entry in $RegKeys) {
    #reset from previous values
    $Key = $null
    $Value = $null
    $Type = $null
    $Data = $null
    $Description = $Null
    #set values
    $Key = $Entry.Key
    $Value = $Entry.Value
    $Type = $Entry.Type
    $Data = $Entry.Data
    $Description = $Entry.Description
    Write-Log -EntryType Information -EventId 99 -Message "Processing Registry Value to '$Description'."

    If ($Key -like 'HKCU\*') {
        $Key = $Key.Replace("HKCU\", "HKLM\Default\")
    }
    
    If ($null -ne $Data -and $Data -ne '') {
        # Output the Registry Key and value name to the restore csv so it can be deleted on restore.
        Add-Content -Path $FileRestore -Value "$Key,$Value,,"        
        $null = cmd /c REG ADD "$Key" /v $Value /t $Type /d "$Data" /f '2>&1'
        Write-Log -EntryType Information -EventId 100 -Message "Added '$Type' Value '$Value' with Value '$Data' to '$Key' with reg.exe.`nReg.exe Exit Code: [$LastExitCode]"
    }
    Else {
        # This is a delete action
        # Get the current value so we can restore it later if needed.
        $keyTemp = $Key.Replace("HKLM\", "HKLM:\")
        If (Get-ItemProperty -Path "$keyTemp" -Name "$Value" -ErrorAction SilentlyContinue) {
            $CurrentRegValue = Get-ItemPropertyValue -Path "$keyTemp" -Name $Value
            If ($CurrentRegValue) {
                Add-Content -Path $FileRestore -Value "$Key,$Value,$type,$CurrentRegValue"        
                Write-Log -EntryType Information -EventId 101 -Message "Stored '$Type' Value '$Value' with value '$CurrentRegValue' to '$Key' to Restore CSV file."
                $null = cmd /c REG DELETE "$Key" /v $Value /f '2>&1'
                Write-Log -EntryType Information -EventId 102 -Message "REG command to delete '$Value' from '$Key' exited with exit code: [$LastExitCode]."
            }
        }        
    }
}
Write-Log -EntryType Information -EventId 105 -Message "Unloading default user hive."
$null = cmd /c REG UNLOAD "HKLM\Default" '2>&1'
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
Else {
    Write-Log -EntryType Information -EventId 106 -Message "Hive unloaded successfully."
}

#endregion Registry Edits

#region Assigned Access Configuration

Write-Log -EntryType Information -EventId 113 -Message "Starting Assigned Access Configuration Section."
. "$DirConfigurationScripts\AssignedAccessWmiBridgeHelpers.ps1"
Set-MultiAppKioskConfiguration -FilePath (Join-Path -Path $DirMultiAppSettings -ChildPath 'MultiApp.xml')
If (Get-MultiAppKioskConfiguration) {
    Write-Log -EntryType Information -EventId 115 -Message "Multi-App Kiosk configuration successfully applied."
}
Else {
    Write-Log -EntryType Error -EventId 116 -Message "Multi-App Kiosk configuration failed. Computer should be restarted first."
    Exit 1        
}
  
#endregion Assigned Access Configuration

If ($ScriptExitCode -eq 1618) {
    Write-Log -EntryType Error -EventId 135 -Message "At least one critical failure occurred. Exiting Script and restarting computer."
    Restart-Computer -Force
}
Else {
    $ScriptExitCode -eq 1641
}
    
Write-Log -EntryType Information -EventId 150 -Message "Updating Group Policy"
$gpupdate = Start-Process -FilePath 'GPUpdate' -ArgumentList '/force' -Wait -PassThru
Write-Log -EntryType Information -EventID 151 -Message "GPUpdate Exit Code: [$($GPUpdate.ExitCode)]"
$null = cmd /c reg add 'HKLM\Software\Kiosk' /v Version /d "$($version.ToString())" /t REG_SZ /f
Write-Log -EntryType Information -EventId 199 -Message "Ending Kiosk Mode Configuration version '$($version.ToString())' with Exit Code: $ScriptExitCode"
Exit $ScriptExitCode
