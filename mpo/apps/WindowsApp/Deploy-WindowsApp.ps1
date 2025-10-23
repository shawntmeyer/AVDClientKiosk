<#
.SYNOPSIS
Deploys or removes the Windows App application package.

.DESCRIPTION
This script installs or uninstalls the Windows App application package using AppxProvisionedPackage

.PARAMETER DeploymentType
Specifies whether to install or uninstall the application. Default is "Install".

.PARAMETER AutologoffEnable
Specifies whether to sign all users out of Windows App and resets app data when the user closes Windows App.

It doesn't impact active Azure Virtual Desktop or Windows 365 sessions.

This behavior will automatically be enabled if either AutoLogoffOnSuccessfulConnect or AutoLogoffTimeInterval are set.

.PARAMETER AutoLogoffOnSuccessfulConnect
Specifies whether to sign all users out of Windows App and reset app data when a successful connection to an Azure Virtual Desktop session host or Windows 365 Cloud PC is made.

It doesn't impact active Azure Virtual Desktop or Windows 365 sessions.

.PARAMETER AutoLogoffTimeInterval
Determines the interval at which Windows App checks the Windows OS for inactivity. For example, if set to 5, the app will poll the OS for inactivity every 5 minutes and the logout process will initiate if the OS reports 5 or more minutes of inactivity.

Additionally, if a user manually closes the app, auto logoff is triggered immediately upon shutdown, clearing relevant app data.
    
.EXAMPLE
.\Deploy-WindowsApp.ps1 
Runs an installation in Passive mode with logging enabled.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -Uninstall
Uninstall Windows App.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -AutologoffEnable
Installs Windows App with autologoff enabled.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -AutoLogoffOnSuccessfulConnect
Installs Windows App with autologoff enabled and configures it to sign out users upon successful connection to an AVD session host or Windows 365 Cloud PC.

.EXAMPLE
.\Deploy-WindowsApp.ps1 -AutoLogoffTimeInterval 15
Installs Windows App with autologoff enabled and configures it to sign out users after 15 minutes of inactivity.

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
    [switch]$AutologoffEnable,

    [Parameter(Mandatory = $false)]
    [switch]$AutoLogoffOnSuccessfulConnect,

    [Parameter(Mandatory = $false)]
    [int]$AutoLogoffTimeInterval
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
    # Configure Auto Logoff Settings
    If ($AutologoffEnable.IsPresent -or $AutoLogoffOnSuccessfulConnect.IsPresent -or $AutoLogoffTimeInterval) {
        Write-Output "Configuring Auto Logoff Settings"
        $RegKey = "HKLM:\SOFTWARE\Microsoft\WindowsApp"
        If (-not (Test-Path -Path $RegKey)) {
            New-Item -Path $RegKey -Force | Out-Null
        }
        Write-Output "Disabling the First Run Experience (FRE)"
        New-ItemProperty -Path $RegKey -Name "SkipFRE" -Value 1 -PropertyType DWord -Force | Out-Null
        If ($AutologoffEnable.IsPresent) {
            Write-Output "Enabling Auto Logoff"
            New-ItemProperty -Path $RegKey -Name "AutoLogoffEnable" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        If ($AutoLogoffOnSuccessfulConnect.IsPresent) {
            Write-Output "Configuring Auto Logoff on Successful Connect"
            New-ItemProperty -Path $RegKey -Name "AutoLogoffOnSuccessfulConnect" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        If ($AutoLogoffTimeInterval) {
            Write-Output "Setting Auto Logoff Time Interval to $AutoLogoffTimeInterval minutes"
            New-ItemProperty -Path $RegKey -Name "AutoLogoffTimeInterval" -Value $AutoLogoffTimeInterval -PropertyType DWord -Force | Out-Null
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