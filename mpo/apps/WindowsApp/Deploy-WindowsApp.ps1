<#
.SYNOPSIS
Deploys or removes the Windows App application package.

.DESCRIPTION
This script installs or uninstalls the Windows App application package using AppxProvisionedPackage

.PARAMETER DeploymentType
Specifies whether to install or uninstall the application. Default is "Install".

.PARAMETER AutoLogoffConfig
Specifies the auto logoff configuration for Windows App. Valid values are:
- 'Disabled': No auto logoff behavior (default)
- 'ResetOnAppCloseOnly': Sign all users out of Windows App and reset app data when the user closes the app
- 'ResetOnIdleTimeOut': Sign all users out of Windows App and reset app data after the specified idle timeout
- 'ResetAfterConnection': Sign all users out of Windows App and reset app data when a successful connection to an Azure Virtual Desktop session host or Windows 365 Cloud PC is made

It doesn't impact active Azure Virtual Desktop or Windows 365 sessions.

.PARAMETER AutoLogoffTimeInterval
Determines the interval in minutes at which Windows App checks the Windows OS for inactivity. This parameter is only used when AutoLogoffConfig is set to 'ResetOnIdleTimeOut'. For example, if set to 15, the app will poll the OS for inactivity every 15 minutes and the logout process will initiate if the OS reports 15 or more minutes of inactivity.

Additionally, if a user manually closes the app, auto logoff is triggered immediately upon shutdown, clearing relevant app data. Default is 15 minutes.

.PARAMETER SkipFRE
Specifies whether to skip the First Run Experience (FRE) for Windows App. Default is $true.
    
.EXAMPLE
.\Deploy-WindowsApp.ps1 
Runs an installation in Passive mode with logging enabled.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -DeploymentType 'Uninstall'
Uninstalls Windows App.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -AutoLogoffConfig 'ResetOnAppCloseOnly'
Installs Windows App with autologoff configured to reset when the user closes the app.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -AutoLogoffConfig 'ResetAfterConnection'
Installs Windows App with autologoff configured to reset upon successful connection to an AVD session host or Windows 365 Cloud PC.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -AutoLogoffConfig 'ResetOnIdleTimeOut' -AutoLogoffTimeInterval 30
Installs Windows App with autologoff configured to reset after 30 minutes of inactivity.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -SkipFRE $false
Installs Windows App but allows the First Run Experience to be shown to users.

.INPUTS
None. You cannot pipe objects to this script.

.OUTPUTS
None by default. Writes status to the pipeline/host; adapt to emit objects if desired.

.NOTES
Author: Shawn Meyer, Microsoft Corporation
Date Created: October 2025
Requires: PowerShell 5.1+ or PowerShell 7+
The product identity and installer path are defined inside the script body.

.LINK
https://learn.microsoft.com/en-us/windows-app/whats-new?tabs=windows
https://learn.microsoft.com/en-us/windows-app/windowsautologoff
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Install", "Uninstall")]
    [string]$DeploymentType = "Install",

    [Parameter(Mandatory = $false)]
    [ValidateSet('Disabled', 'ResetOnAppCloseOnly', 'ResetOnIdleTimeOut', 'ResetAfterConnection')]
    [switch]$AutoLogoffConfig = 'Disabled',

    [Parameter(Mandatory = $false)]
    [int]$AutoLogoffTimeInterval = 15,

    [Parameter(Mandatory = $false)]
    [bool]$SkipFRE = $true
)

#region Initialization

$SoftwareName = 'Windows App'
$Url = 'https://go.microsoft.com/fwlink/?linkid=2262633'
$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Args = $null
$Script:LogDir = Join-Path -Path "$Env:SystemRoot\Logs" -ChildPath 'Software'


If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Try {

        foreach ($k in $MyInvocation.BoundParameters.keys) {
            switch ($MyInvocation.BoundParameters[$k].GetType().Name) {
                "SwitchParameter" { if ($MyInvocation.BoundParameters[$k].IsPresent) { $Script:Args += "-$k " } }
                "String" { $Script:Args += "-$k `"$($MyInvocation.BoundParameters[$k])`" " }
                "Int32" { $Script:Args += "-$k $($MyInvocation.BoundParameters[$k]) " }
                "Boolean" { $Script:Args += "-$k `$$($MyInvocation.BoundParameters[$k]) " }
            }
        }
        If ($Script:Args) {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`" $($Script:Args)" -Wait -NoNewWindow
        }
        Else {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`"" -Wait -NoNewWindow
        }
    }
    Catch {
        Throw "Failed to start 64-bit PowerShell"
    }
    Exit
}

Function Set-RegistryValue {
    [CmdletBinding()]
    param (
        [string]$Name,
        [string]$Path,
        [string]$PropertyType,
        [string]$Value
    )
    Write-Verbose "[Set-RegistryValue]: Setting Registry Value: $Name"
    If (!(Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    $RemoteValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    If ($RemoteValue) {
        $CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name
        If ($Value -ne $CurrentValue) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force | Out-Null
        }
    }
    Else {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
}

If (-not (Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Directory -Force | Out-Null
}

If ($DeploymentType -ne "Uninstall") {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path $Script:LogDir -ChildPath $Script:LogName) -Force
    $CurrentVersion = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "MicrosoftCorporationII.Windows365" }
    If ($CurrentVersion) {
        Write-Output "Removing existing version of $SoftwareName"
        $CurrentVersion | Remove-AppxProvisionedPackage -Online
    }
    $MSIXPath = (Get-ChildItem -Path $PSScriptRoot -filter *.msix).FullName
    If (-not ($MSIXPath)) {
        Write-Output "Windows App MSIX package not found in $PSScriptRoot"
        Write-Output "Attempting to download from '$Url'"
        $tempDir = Join-Path -Path $env:Temp -ChildPath "$($Script:Name)"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        $MSIXPath = Join-Path -Path $env:Temp -ChildPath 'WindowsApp.msix'
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $MSIXPath -UseBasicParsing
        If (Test-Path -Path $MSIXPath) {
            Write-Output "Windows App MSIX package downloaded to: $MSIXPath"
        }
        else {
            Write-Error "Windows App MSIX package not found"
            Exit 1
        }
    }
    Else {
        Write-Output "Windows App MSIX package found in $PSScriptRoot"
    }

    $DependenciesPath = (Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "Dependencies") -filter *.appx).FullName

    # Provision the app with dependencies
    Add-AppxProvisionedPackage -Online -PackagePath $MSIXPath -DependencyPackagePath $DependenciesPath -SkipLicense
    
    # Skip First Run Experience
    If ($SkipFRE) {
        Write-Output "Disabling the First Run Experience (FRE)"
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows365" -Name "SkipFRE" -Value 1 -PropertyType DWord
    }

    # Configure Auto Logoff Settings
    If ($null -ne $AutoLogoffConfig -and $AutoLogoffConfig -ne 'Disabled') {
        $RegKey = "HKLM:\SOFTWARE\Microsoft\WindowsApp"
        #    [ValidateSet('Disabled', 'ResetOnAppCloseOnly', 'ResetOnIdleTimeOut', 'ResetAfterConnection')]
        Switch ($AutologoffConfig) {
            'ResetOnAppCloseOnly' {
                Set-RegistryValue -Path $RegKey -Name "AutoLogoffEnable" -Value 1 -PropertyType DWord
            }
            'ResetOnIdleTimeOut' {
                Set-RegistryValue -Path $RegKey -Name 'AutoLogoffTimeInterval' -Value $AutoLogoffTimeInterval -PropertyType DWord
            }
            'ResetAfterConnection' {
                Set-RegistryValue -Path $RegKey -Name 'AutoLogoffOnSuccessfulConnect' -Value 1 -PropertyType DWord
            }
        }

    }
    
    if ($tempDir -and (Test-Path -Path $tempDir)) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Else {
    [string]$Script:LogName = "Uninstall" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path $Script:LogDir -ChildPath $Script:LogName) -Force
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "MicrosoftCorporationII.Windows365" } | Remove-AppxProvisionedPackage -Online
    Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -like "MicrosoftCorporationII.Windows365*" } | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    # REMOVE AUTO LOGOFF SETTINGS
    $RegKey = "HKLM:\SOFTWARE\Microsoft\WindowsApp"
    If (Test-Path -Path $RegKey) {
        Write-Output "Removing Auto Logoff Settings"
        Remove-Item -Path $RegKey -Recurse -Force | Out-Null
    }
}

Stop-Transcript