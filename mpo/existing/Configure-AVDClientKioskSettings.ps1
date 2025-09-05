<# 
.SYNOPSIS
    This script copies a PowerShell script to the system that is used to launch the Remote Desktop client (MSRDCW).

.DESCRIPTION 
    This script completes a series of configuration tasks based on the parameters chosen. These tasks can include:

    * Create a AVDClientLauncher directory at the root of the system drive.
    * Set ACLs on the AVDClientLauncher directory to prevent Non-Administrators from changing files.
    * Copy the Launch-AVDClient.ps1 and Launch-AVDClient.vbs scripts to the AVDClientLauncher directory.
    * Dynamically update the parameters of the Launch-AVDClient.ps1 script.
    * Create a custom Remote Desktop Client shortcut in the Start Menu if the CreateStartMenuShortcut switch parameter is used.
    * Disable Workplace Join to stop the stay signed in prompt in the AVD Client.
    * Write the version of the script to the registry to be used for application detection in Configuration Manager or Intune.

.NOTES 
     

.COMPONENT 
    No PowerShell modules required.

.LINK 
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-windows?tabs=subscribe
    https://learn.microsoft.com/en-us/azure/virtual-desktop/uri-scheme
 

.PARAMETER Version
    This version parameter allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager
    or Microsoft Endpoint Configuration Manager by querying the value of the registry value: HKLM\Software\Kiosk\version.

.PARAMETER EnvironmentAVD
    This value determines the Azure environment to which you are connecting. It ultimately determines the Url of the Remote Desktop Feed which
    varies by environment by setting the $SubscribeUrl variable and replacing placeholders in several files during installation. Leave this value blank
    to allow connection to different Azure clouds from this client. In this case, the user will have to click the Subscribe button to start the logon process.
    The list of Urls can be found at
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-microsoft-store?source=recommendations#subscribe-to-a-workspace.

.PARAMETER InstallAVDClient
    This switch parameter determines if the latest Visual C++ Redistributables and Remote Desktop client for Windows is automatically downloaded from the
    Internet and installed on the system prior to configuration.

#>
[CmdletBinding()]
param (
    [version]$Version = '1.0.0',

    [ValidateSet('AzureCloud', 'AzureUSGovernment')]
    [string]$EnvironmentAVD='AzureUSGovernment',

    [switch]$InstallAVDClient,

    [string]$DirAVDClientLauncher = 'C:\AVDClientLauncher'
)

#region Set Variables

$Script:FullName = $MyInvocation.MyCommand.Path
$EventLog = 'AVD Client Launcher'
$EventSource = 'Configuration Script'
$LaunchScriptEventSource = 'Launch Script'
# Set AVD feed subscription Url.
If ($EnvironmentAVD -eq 'AzureUSGovernment') {
    $SubscribeUrl = 'https://rdweb.wvd.azure.us'
}
Elseif ($EnvironmentAVD -eq 'AzureCloud') {
    $SubscribeUrl = 'https://client.wvd.microsoft.com'
}
Else {
    $SubscribeUrl = $null
}

#endregion Set Variables

#region Functions

Function Set-RegistryValue {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Name,
        [Parameter()]
        [string]
        $Path,
        [Parameter()]
        [string]$PropertyType,
        [Parameter()]
        $Value
    )

    Write-Verbose "[Set-RegistryValue]: Setting Registry Value: $Name"
    # Create the registry Key(s) if necessary.
    If (!(Test-Path -Path $Path)) {
        Write-Verbose "[Set-RegistryValue]: Creating Registry Key: $Path"
        New-Item -Path $Path -Force | Out-Null
    }
    # Check for existing registry setting
    $RemoteValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    If ($RemoteValue) {
        # Get current Value
        $CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name
        Write-Verbose "[Set-RegistryValue]: Current Value of $($Path)\$($Name) : $CurrentValue"
        If ($Value -ne $CurrentValue) {
            Write-Log -message "[Set-RegistryValue]: Setting Value of $($Path)\$($Name) : $Value"
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force | Out-Null
        }
        Else {
            Write-Verbose "[Set-RegistryValue]: Value of $($Path)\$($Name) is already set to $Value"
        }           
    }
    Else {
        Write-Verbose "[Set-RegistryValue]: Setting Value of $($Path)\$($Name) : $Value"
        New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
    Start-Sleep -Milliseconds 500    
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
New-EventLog -LogName $EventLog -Source $LaunchScriptEventSource -ErrorAction SilentlyContinue
Write-Log -EntryType Information -EventId 1 -Message "Executing '$Script:FullName'."
#endregion

#region AVDClient Directory

Write-Log -EntryType Information -EventID 10 -Message "Creating Directory - '$DirAVDClientLauncher'."
If (-not (Test-Path $DirAVDClientLauncher)) {
    New-Item -Path $DirAVDClientLauncher -ItemType Directory -Force | Out-Null
}

# Setting ACLs on the AVD Client Launcher directory to prevent Non-Administrators from changing files. Defense in Depth.
Write-Log -EntryType Information -EventId 11 -Message "Configuring $DirAVDClientLauncher Directory ACLs"
$Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
$ACL = Get-ACL $DirAVDClientLauncher
$ACL.SetOwner($Group)
Set-ACL -Path $DirAVDClientLauncher -AclObject $ACL
Update-ACL -Path $DirAVDClientLauncher -Identity 'BuiltIn\Administrators' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACL -Path $DirAVDClientLauncher -Identity 'BuiltIn\Users' -FileSystemRights 'ReadAndExecute' -Type 'Allow'
Update-ACL -Path $DirAVDClientLauncher -Identity 'System' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACLInheritance -Path $DirAVDClientLauncher -DisableInheritance $true -PreserveInheritedACEs $false

# Copy Client Launch Scripts.
Write-Log -EventID 15 -Message "Copying Launch AVD Client Scripts from '$PSScriptRoot' to '$DirAVDClientLauncher'"
Copy-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Launch-AVDClient.ps1') -Destination $DirAVDClientLauncher -Force
Copy-Item -Path (Join-Path -Path $PSSCriptRoot -ChildPath 'Launch-AVDClient.vbs') -Destination $DirAVDClientLauncher -Force
# dynamically update parameters of launch script.
$FileToUpdate = "$DirAVDClientLauncher\Launch-AVDClient.ps1"
$Content = Get-Content -Path $FileToUpdate
$Content = $Content.Replace('[string]$EventLog', -Join ('[string]$EventLog', ' = "', $EventLog, '"'))
$Content = $Content.Replace('[string]$EventSource', -Join ('[string]$EventSource', ' = "', $LaunchScriptEventSource, '"'))
If ($SubscribeUrl) {
    $Content = $Content.Replace('[string]$SubscribeUrl', -Join ('[string]$SubscribeUrl', ' = "', $SubscribeUrl, '"'))
}
$Content | Set-Content -Path $FileToUpdate

#region Registry Edits

Set-RegistryValue -Name 'BlockAADWorkplaceJoin' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' -PropertyType 'DWORD' -Value 1
New-Item -Path 'Registry::HKEY_CLASSES_ROOT\ms-avdclientlauncher' -Value 'URL:ms-avdclientlauncher' -Force | Out-Null
Set-RegistryValue -Name 'URL Protocol' -Path 'Registry::HKEY_CLASSES_ROOT\ms-avdclientlauncher' -PropertyType 'String' -Value ''
New-Item -Path 'Registry::HKEY_CLASSES_ROOT\ms-avdclientlauncher\shell\open\command' -Value "$env:SystemRoot\System32\wscript.exe `"$DirAVDClientLauncher\Launch-AVDClient.vbs`" `"%1`"" -ItemType STRING -Force | Out-Null
Set-RegistryValue -Name 'Version' -Path 'HKLM:\Software\AVDClientLauncher' -PropertyType 'String' -Value "$($version.ToString())"

#endregion Registry Edits

Write-Log -EventID 50 -Message "Ending Kiosk Mode Configuration version '$($version.ToString())'."
