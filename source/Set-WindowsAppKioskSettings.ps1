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
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-windows?tabs=subscribe
    https://learn.microsoft.com/en-us/azure/virtual-desktop/uri-scheme
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview
    https://learn.microsoft.com/en-us/windows/configuration/kiosk-shelllauncher
    https://public.cyber.mil/stigs/gpo/
 
.PARAMETER ApplySTIGs
This switch parameter determines If the latest DoD Security Technical Implementation Guide Group Policy Objects are automatically downloaded
from https://public.cyber.mil/stigs/gpo and applied via the Local Group Policy Object (LGPO) tool to the system. If they are, then several
delta settings are applied to allow the system to communicate with Azure Active Directory and complete autologon (If applicable).

.PARAMETER AutoLogon
This switch parameter determines If autologon is enabled through the Shell Launcher configuration. The Shell Launcher feature will automatically
create a new user - 'KioskUser0' - which will not have a password and be configured to automatically logon when Windows starts.

.PARAMETER SingleAppKiosk
This switch parameter determines whether the Windows Shell is replaced by the Remote Desktop client for Windows or remains the default 'explorer.exe'.
When the default 'explorer' shell is used additional local group policy settings and provisioning packages are applied to lock down the shell.

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

.PARAMETER ShowSettings
This switch parameter determines If the Settings App appears on the start menu. The settings app and control panel are restricted to the applets/pages specified in the nonadmins-ShowSettings.txt file. If this value is not set,
then the Settings app and Control Panel are not displayed or accessible.

.PARAMETER DeviceRemovalAction
This string parameter determines what occurs when a FIDO Passkey device or SmartCard is removed from the system. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When AutoLogon is true, you can leave this empty or choose only 'ResetClient'.
When AutoLogon is false, you can leave this empty or choose 'Lock' or 'Logoff'. You must also use the SmartCard switch parameter or specify a 'DeviceVendorID'.

.PARAMETER DeviceVendorID
This string parameter defines the Vendor ID of the hardware authentication token that if removed will trigger the action defined in "DeviceRemovalAction".
This value is only used when "DeviceRemovalAction" contains a value.

.PARAMETER SmartCard
This switch parameter determines if SmartCard removal will trigger the 'DeviceRemovalAction'. This value is only used when 'DeviceRemovalAction' contains a value.

.PARAMETER IdleTimeoutAction
This string parameter determines what occurs when the system is idle for a specified amount of time. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When AutoLogon is true, you can leave this empty or choose only 'ResetClient'.
When AutoLogon is false, you can leave this empty or choose 'Lock' or 'Logoff'.

.PARAMETER IdleTimeOut
This integer value determines the number of seconds in the that system will wait before performing the action specified in the IdleTimeoutAction parameter.

.PARAMETER SystemDisconnectAction
This string parameter determines what occurs when the remote desktop session connection is disconnected by the system. This could be due to an IdleTimeout on the session host in the SSO scenario or
the user has initiated a connection to the session host from another client. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When AutoLogon is true, you can leave this empty or choose only 'ResetClient'.
When AutoLogon is false, you can leave this empty or choose 'Lock' or 'Logoff'.

.PARAMETER UserDisconnectSignOutAction
This string parameter determines what occurs when the user disconnects or signs out from the remote session. The possible values are 'Lock', 'Logoff', or 'ResetClient'.
When AutoLogon is true, you can leave this empty or choose only 'ResetClient'.
When AutoLogon is false, you can leave this empty or choose 'Lock' or 'Logoff'.

.PARAMETER Version
This version parameter allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager or Microsoft Endpoint Configuration Manager by querying the value of the registry value: HKLM\Software\Kiosk\version.

#>
[CmdletBinding()]
param (
    [switch]$ApplySTIGs,

    [Parameter(Mandatory, ParameterSetName = 'AutologonSingleAppKiosk')]
    [Parameter(Mandatory, ParameterSetName = 'AutoLogonMultiAppKiosk')]
    [switch]$AutoLogon,

    [int]$IdleTimeoutInMinutes = 15,

    [ValidateSet('Lock', 'ResetClient')]
    [string]$IdleTimeoutAction,

    [switch]$InstallWindowsApp,

    [Parameter(Mandatory, ParameterSetName = 'DirectLogonSingleAppKiosk')]
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

#region Parameter Validation and Configuration
$ActionParameters = @($SmartCardRemovalAction, $IdleTimeoutAction)
If ($AutoLogon) {
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
$EventLog = 'AVD Client Kiosk'
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
$DirSingleAppKioskSettings = Join-Path -Path $DirAssignedAccess -ChildPath 'SingleApp'
$DirGPO = Join-Path -Path $Script:Dir -ChildPath "GPOSettings"
$DirKiosk = Join-Path -Path $env:SystemDrive -ChildPath "KioskSettings"
$DirRegKeys = Join-Path -Path $Script:Dir -ChildPath "RegistryKeys"
$FileRegKeys = Join-Path -Path $DirRegKeys -ChildPath "RegKeys-WindowsApp.csv"
$DirTools = Join-Path -Path $Script:Dir -ChildPath "Tools"
$DirUserLogos = Join-Path -Path $Script:Dir -ChildPath "UserLogos"
$DirConfigurationScripts = Join-Path -Path $Script:Dir -ChildPath "Scripts\Configuration"

# Detect Wifi Adapter in order to show Wifi Settings in system tray when necessary.
$WifiAdapter = Get-NetAdapter | Where-Object { $_.Name -like '*Wi-Fi*' -or $_.Name -like '*Wifi*' -or $_.MediaType -like '*802.11*' }     
    
# Set default exit code to 0
$ScriptExitCode = 0

#region Functions

Function Get-PendingReboot {
    <#
    .SYNOPSIS
        Gets the pending reboot status on a local or remote computer.

    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
        system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
        Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
        CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
        and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
        
        CBServicing = Component Based Servicing (Windows 2008+)
        WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
        PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
        PendFileRename = PendingFileRenameOperations (Windows 2003+)
        PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                        Virus leverage this key for def/dat removal, giving a false positive PendingReboot

    .EXAMPLE
        Get-PendingReboot
        
    .LINK

    .NOTES
    #>
    Try {
        ## Setting pending values to false to cut down on the number of else statements
        $RebootPending = $false
        $CompPendRen = $false
        $PendFileRename = $false
        $SCCM = $false

        ## Setting CBSRebootPend to null since not all versions of Windows has this value
        $CBSRebootPend = $null

        ## Making registry connection to the local/remote computer
        $HKLM = [UInt32] "0x80000002"
        $WMI_Reg = [WMIClass] "\\.\root\default:StdRegProv"
						
        ## query the CBS Reg Key
	    
        $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
        $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
	    							
        ## Query WUAU from the registry
        $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
        $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
						
        ## Query PendingFileRenameOperations from the registry
        $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
        $RegValuePFRO = $RegSubKeySM.sValue

        ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
        $Netlogon = $WMI_Reg.EnumKey($HKLM, "SYSTEM\CurrentControlSet\Services\Netlogon").sNames
        $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

        ## Query ComputerName and ActiveComputerName from the registry
        $ActCompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")            
        $CompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")

        If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
            $CompPendRen = $true
        }
						
        ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
        If ($RegValuePFRO) {
            $PendFileRename = $true
        }

        ## Determine SCCM 2012 Client Reboot Pending Status
        ## To avoid nested 'If' statements and unneeded WMI calls to determine If the CCM_ClientUtilities class exist, setting EA = 0
        
        ## Try CCMClientSDK
        Try {
            $CCMClientSDK = Invoke-WmiMethod -ComputerName LocalHost -Namespace 'ROOT\ccm\ClientSDK' -Class 'CCM_ClientUtilities' -Name DetermineIfRebootPending -ErrorAction 'Stop'
        }
        Catch {
            $CCMClientSDK = $null
        }

        If ($CCMClientSDK) {
            If ($CCMClientSDK.ReturnValue -ne 0) {
                Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
            }
            If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
                $SCCM = $true
            }
        }
        Else {
            $SCCM = $False
        }
        If ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename) { $RebootPending = $true }
        Return $RebootPending

    }
    Catch {
        Write-Warning "$_"				
    }						
}

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
        'Information' { Write-Host $Message }
        'Warning' { Write-Warning $Message }
        'Error' { Write-Error $Message }
    }
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
& "$Script:Dir\Remove-KioskSettings.ps1" -Reinstall

#endregion Previous Version Removal

#region Remove Apps

# Remove Built-in Windows 11 Apps on non LTSC builds of Windows
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

#region STIGs

If ($ApplySTIGs) {
    Write-Log -EntryType Information -EventId 27 -Message "Running Script to apply the latest STIG group policy settings via LGPO for Windows 10, Internet Explorer, Microsoft Edge, Windows Firewall, and Defender AntiVirus."
    & "$DirConfigurationScripts\Apply-LatestSTIGs.ps1"
    If ($AutoLogon) {
        # Remove Logon Banner
        Write-Log -EntryType Information -EventId 28 -Message "Running Script to remove the logon banner because this is an autologon kiosk."
        & "$DirConfigurationScripts\Apply-STIGAutoLogonExceptions.ps1"
    }
    Else {        
        Write-Log -EntryType Information -EventId 28 -Message "Running Script to allow PKU2U online identities required for AAD logon."
        & "$DirConfigurationScripts\Apply-STIGDirectSignOnExceptions.ps1"
    }
}

#endregion STIGs

#region Install AVD Client

If ($InstallWindowsApp) {
    Write-Log -EntryType Information -EventID 30 -Message "Running Script to install or update Visual C++ Redistributables."
    & "$DirApps\VisualC++Redistributables\Install-VisualC++Redistributables.ps1"
    Write-Log -EntryType Information -EventId 31 -Message "Running Script to install or update the Windows App."
    & "$DirApps\WindowsApp\Install-WindowsApp.ps1"
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

$null = cmd /c lgpo.exe /t "$DirGPO\computer-userlogos.txt" '2>&1'
Write-Log -EntryType Information -EventId 55 -Message "Configured User Logos to use default via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
Write-Log -EntryType Information -EventId 56 -Message "Backing up current User Logo files to '$DirKiosk\UserLogos'."
Copy-Item -Path "$env:ProgramData\Microsoft\User Account Pictures" -Destination "$DirKiosk\UserLogos" -Force
Write-Log -EntryType Information -EventId 57 -Message "Copying User Logo files to '$env:ProgramData\Microsoft\User Account Pictures'."
Get-ChildItem -Path $DirUserLogos | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force

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
    If ($IdleTimeoutActon -eq 'Lock') {
        # Will lock the system via the inactivity timeout built-in policy which locks the screen after inactivity.
        $sourceFile = Join-Path -Path $DirGPO -ChildPath 'MachineInactivityTimeout.inf'
        $outFile = Join-Path -Path "$env:SystemRoot\SystemTemp" -ChildPath 'MachineInactivityTimeout.inf'
        (Get-Content -Path $SourceFile).Replace('900', ($IdleTimeoutInMinutes * 60)) | Out-File $outFile
        $null = cmd /c lgpo /s "$outFile" '2>&1'
        Write-Log -EntryType Information -EventId 85 -Message "Set 'Interactive logon: Machine inactivity limit' to '$($IdleTimeout * 60) seconds' via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
        Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
    }
}

#endregion Local GPO Settings

#region Registry Edits

# update the Default User Hive to Hide the search button and task view icons on the taskbar.
$null = cmd /c REG LOAD "HKLM\Default" "$env:SystemDrive\Users\default\ntuser.dat" '2>&1'
Write-Log -EntryType Information -EventId 95 -Message "Loaded Default User Hive Registry Keys via Reg.exe.`nReg.exe Exit Code: [$LastExitCode]"

# Import registry keys file
Write-Log -EntryType Information -EventId 96 -Message "Loading Registry Keys from CSV file."
$RegKeys = Import-Csv -Path $FileRegKeys
If ($AutoLogon) {
    #Configure AutoLogoff for the Windows App
    #https://learn.microsoft.com/en-us/windows-app/windowsautologoff
    $NewEntry = [PSCustomObject]@{
        Key         = 'HKLM\SOFTWARE\Microsoft\WindowsApp'
        Value       = 'AutoLogoffEnable'
        Type        = 'REG_DWORD'
        Data        = 1
        Description = 'Enable AutoLogoff for Windows App'
    }
    $RegKeys += $NewEntry

    $NewEntry = [PSCustomObject]@{
        Key         = 'HKLM\SOFTWARE\Microsoft\WindowsApp'
        Value       = 'SkipFRE'
        Type        = 'REG_DWORD'
        Data        = 1
        Description = 'Disable First Fun Experience in Windows App'
    }
    $RegKeys += $NewEntry

    If ($IdleTimeoutAction -eq 'ResetClient') {
        $NewEntry = [PSCustomObject]@{
            Key         = 'HKLM\SOFTWARE\Microsoft\WindowsApp'
            Value       = 'AutoLogoffTimeInterval'
            Type        = 'REG_DWORD'
            Data        = $IdleTimeoutInMinutes
            Description = 'Set AutoLogoff Timeout for Windows App'
        }
        $RegKeys += $NewEntry
    }

}
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

#region Shell Launcher Configuration

Write-Log -EntryType Information -EventId 113 -Message "Starting Assigned Access Configuration Section."
. "$DirConfigurationScripts\AssignedAccessWmiBridgeHelpers.ps1"
If ($SingleAppKiosk) {
    If ($AutoLogon) {
        $configFile = Join-Path -Path $DirSingleAppKioskSettings -ChildPath "WindowsApp_AutoLogon.xml"
        Write-Log -EntryType Information -EventId 114 -Message "Enabling Single App Kiosk Windows App with Autologon via WMI MDM bridge."
    }
    Else {
        $configFile = Join-Path -Path $DirSingleAppKioskSettings -ChildPath "WindowsApp.xml"
        Write-Log -EntryType Information -EventId 114 -Message "Enabling Single App Kiosk Windows App via WMI MDM bridge."
    }
}
Else {
    If ($AutoLogon) {
        If ($ShowSettings) {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App with Settings and Autologon."
            $configFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_Settings_Autologon.xml"
        }
        Else {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App and Autologon."
            $configFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_Autologon.xml"
        }
    }
    Else {
        If ($ShowSettings) {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App and Settings."
            $configFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp_Settings.xml"
        }
        Else {
            Write-Log -EntryType Information -EventId 113 -Message "Configuring MultiApp Kiosk settings for Windows App."
            $configFile = Join-Path -Path $DirMultiAppSettings -ChildPath "WindowsApp.xml"
        }
    }
    Write-Log -EntryType Information -EventId 114 -Message "Configuration File = $configFile"
    $destFile = Join-Path $DirKiosk -ChildPath 'MultiAppKioskConfiguration.xml'
    Copy-Item -Path $configFile -Destination $destFile -Force
    Set-AssignedAccessConfiguration -FilePath $destFile
    If (Get-AssignedAccessConfiguration) {
        Write-Log -EntryType Information -EventId 115 -Message "Assigned Access configuration successfully applied."
    }
    Else {
        Write-Log -EntryType Error -EventId 116 -Message "Assigned Access configuration failed. Computer should be restarted first."
        Exit 1        
    }
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
$gpupdate = Start-Process -FilePath 'GPUpdate' -ArgumentList '/force' -Wait -PassThru
Write-Log -EntryType Information -EventID 151 -Message "GPUpdate Exit Code: [$($GPUpdate.ExitCode)]"
$null = cmd /c reg add 'HKLM\Software\Kiosk' /v Version /d "$($version.ToString())" /t REG_SZ /f
Write-Log -EntryType Information -EventId 199 -Message "Ending Kiosk Mode Configuration version '$($version.ToString())' with Exit Code: $ScriptExitCode"
Exit $ScriptExitCode
