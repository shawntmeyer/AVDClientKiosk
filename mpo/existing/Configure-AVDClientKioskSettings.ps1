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
    [string]$EnvironmentAVD,

    [switch]$InstallAVDClient
)

#region Set Variables

$Script:FullName = $MyInvocation.MyCommand.Path
$Script:Dir = Split-Path $Script:FullName
$Script:File = [string]$myInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
# Log file (.log)
$Script:LogDir = Join-Path -Path $env:SystemRoot -ChildPath "Logs"
$date = Get-Date -UFormat "%Y-%m-%d %H-%M-%S"
$Script:LogName = "$($Script:Name)-$date.log"
# Source Directories and supporting files
$DirAVDClientLauncher = Join-Path -Path $env:SystemDrive -ChildPath "AVDClientLauncher"

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

#region Restart Script in 64-bit powershell if necessary

If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    $scriptArguments = $null
    Try {
        foreach ($k in $PSBoundParameters.keys) {
            switch ($PSBoundParameters[$k].GetType().Name) {
                "SwitchParameter" { If ($PSBoundParameters[$k].IsPresent) { $scriptArguments += "-$k " } }
                "String" { If ($PSBoundParameters[$k] -match '_') { $scriptArguments += "-$k `"$($PSBoundParameters[$k].Replace('_',' '))`" " } Else { $scriptArguments += "-$k `"$($PSBoundParameters[$k])`" " } }
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

#endregion Restart Script in 64-bit powershell if necessary

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

#endregion Functions

#region Initialization

If (-not (Test-Path $Script:LogDir)) {
    $null = New-Item -Path $Script:LogDir -ItemType Directory -Force
}

Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force

#endregion

#region Install AVD Client

If ($installAVDClient) {
    Write-Output "Running Script to install or update Visual C++ Redistributables."
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Install-VisualC++Redistributables.ps1')
    Write-Output "Running Script to install or update AVD Client."
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Install-AVDClient.ps1')
}

#endregion

#region AVDClient Directory

Write-Output "Creating AVDClientLauncher Directory at root of system drive."
If (-not (Test-Path $DirAVDClientLauncher)) {
    New-Item -Path $DirAVDClientLauncher -ItemType Directory -Force | Out-Null
}

# Setting ACLs on the AVD Client Launcher directory to prevent Non-Administrators from changing files. Defense in Depth.
Write-Output "Configuring Kiosk Directory ACLs"
$Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
$ACL = Get-ACL $DirAVDClientLauncher
$ACL.SetOwner($Group)
Set-ACL -Path $DirAVDClientLauncher -AclObject $ACL
Update-ACL -Path $DirAVDClientLauncher -Identity 'BuiltIn\Administrators' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACL -Path $DirAVDClientLauncher -Identity 'BuiltIn\Users' -FileSystemRights 'ReadAndExecute' -Type 'Allow'
Update-ACL -Path $DirAVDClientLauncher -Identity 'System' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACLInheritance -Path $DirAVDClientLauncher -DisableInheritance $true -PreserveInheritedACEs $false

# Copy Client Launch Scripts.
Write-Output "Copying Launch AVD Client Scripts from '$PSScriptRoot' to '$DirAVDClientLauncher'"
Copy-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Launch-AVDClient.ps1') -Destination $DirAVDClientLauncher -Force
Copy-Item -Path (Join-Path -Path $PSSCriptRoot -ChildPath 'Launch-AVDClient.vbs') -Destination $DirAVDClientLauncher -Force
# dynamically update parameters of launch script.
$FileToUpdate = "$DirAVDClientLauncher\Launch-AVDClient.ps1"
If ($SubscribeUrl) {
    $Content = Get-Content -Path $FileToUpdate
    $Content = $Content.Replace('[string]$SubscribeUrl', -Join ('[string]$SubscribeUrl', ' = "', $SubscribeUrl, '"'))
    $Content | Set-Content -Path $FileToUpdate
}
#region Registry Edits

Set-RegistryValue -Name 'BlockAADWorkplaceJoin' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' -PropertyType 'DWORD' -Value 1
New-Item -Path 'HKCR:\ms-avdclientlauncher' -Value 'URL:ms-avdclientlauncher' -Force | Out-Null
Set-RegistryValue -Name 'URL Protocol' -Path 'HKCR:\ms-avdclientlauncher' -PropertyType 'String' -Value ''
New-Item -Path 'HKCR:\ms-avdclientlauncher\shell\open\command' -Value "$env:SystemRoot\System32\wscript.exe `"$DirAVDClientLauncher\Launch-AVDClient.vbs`"" -ItemType STRING -Force | Out-Null
Set-RegistryValue -Name 'Version' -Path 'HKLM:\Software\AVDClientLauncher' -PropertyType 'String' -Value "$($version.ToString())"

#endregion Registry Edits

Write-Output "Ending Kiosk Mode Configuration version '$($version.ToString())'."
Stop-Transcript