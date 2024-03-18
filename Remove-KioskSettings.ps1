[CmdletBinding()]
param (
    # Reinstall Kiosk Settings. If called from Installation Script this will be chosen.
    [Parameter()]
    [switch]$Reinstall
)

#region Set Variables
$script:FullName = $MyInvocation.MyCommand.Path
$script:Dir = Split-Path $script:FullName
$Script:File = [string]$myInvocation.MyCommand.Name
[String]$Script:LogDir = Join-Path -Path $env:SystemRoot -ChildPath "Logs"
$date = Get-Date -UFormat "%Y-%m-%d %H-%M-%S"
$Script:LogName = [io.path]::GetFileNameWithoutExtension($Script:File) + "-$date.log"
$GPODir = "$Script:Dir\gposettings"
$ToolsDir = "$Script:Dir\Tools"
$DirConfigurationScripts = "$Script:Dir\Scripts\Configuration"
$KioskDir = "$env:SystemDrive\KioskSettings"
$ProvisioningPackagesDir = "$KioskDir\ProvisioningPackages"
$RegKeysRestoreFile = "$KioskDir\RegKeyRestore.csv"
$AppLockerRestoreFile = "$KioskDir\ApplockerPolicy.xml"
# Event Log Information
$EventLog = 'AVD Client Kiosk'
$EventSource = 'Configuration Removal Script'

#endregion Set Variables

#region Restart Script in 64-bit powershell if necessary

If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    $scriptArguments = $null
    Try {
        foreach($k in $PSBoundParameters.keys)
        {
            switch($PSBoundParameters[$k].GetType().Name)
            {
                "SwitchParameter" {if($PSBoundParameters[$k].IsPresent) { $scriptArguments += "-$k " } }
                "String"          { $scriptArguments += "-$k `"$($PSBoundParameters[$k])`" " }
                "Int32"           { $scriptArguments += "-$k $($PSBoundParameters[$k]) " }
                "Boolean"         { $scriptArguments += "-$k `$$($PSBoundParameters[$k]) " }
                "Version"          { $scriptArguments += "-$k `"$($PSBoundParameters[$k])`" " }
            }
        }
        If ($null -ne $scriptArguments) {
            $RunScript = Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$PSCommandPath`" $scriptArguments" -PassThru -Wait -NoNewWindow
        } Else {
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
        [ValidateSet('Information','Warning','Error')]
        $EntryType = 'Information',
        [Parameter()]
        [Int]
        $EventID,
        [Parameter()]
        [string]
        $Message
    )
    If ($EntryType -eq 'Error') {
        Write-Error $Message
    } Elseif ($EntryType -eq 'Warning') {
        Write-Warning -Message $Message
    } Else {
        Write-Output $Message
    }
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType $EntryType -EventId $EventId -Message $Message -ErrorAction SilentlyContinue
}

#endregion Functions

#region Initialization and Logging

New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction SilentlyContinue

If (-not (Test-Path $Script:LogDir)) {
    $null = New-Item -Path $Script:LogDir -ItemType Directory -Force
}
Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
Write-Log -EntryType Information -EventId 5 -Message "Executing '$Script:FullName'."

#endregion Initialization and Logging

#region Main Script

# Removing Embedded Shells Configuration

. "$DirConfigurationScripts\AssignedAccessWmiBridgeHelpers.ps1"
If (Get-ShellLauncherConfiguration) {
    Write-Log -EventId 6 -EntryType Information -Message "Removing Shell Launcher settings via WMI Bridge."
    Clear-ShellLauncherConfiguration
}

If (Get-MultiAppKioskConfiguration) {
    Write-Log -EventId 6 -EntryType Information -Message "Removing Multi-App Kiosk Configuration via WMI Bridge."
    Clear-MultiAppKioskConfiguration
}

# Removing Non-Administrators Local GPO.
$DirNonAdminsGPO = "$env:SystemRoot\System32\GroupPolicyUsers\S-1-5-32-545"
If (Test-Path -Path $DirNonAdminsGPO) {
    Write-Log -EventId 7 -EntryType Information -Message "Deleting Non-Administrators local group policy object and forcing GPUpdate."
    Remove-Item -Path $DirNonAdminsGPO -Recurse -Force -ErrorAction SilentlyContinue
    If (!(Test-Path -Path $DirNonAdminsGPO)) {
        Write-Log -EventId 8 -EntryType Information -Message "Non-Administrators Local GPO removed successfully."
        Start-Process -FilePath "gpupdate.exe" -ArgumentList "/Force" -Wait -ErrorAction SilentlyContinue
    }
    Else {
        Write-Log -EventId 9 -EntryType Error -Message "Non-Administrators Local GPO folder was not removed successfully."
        Exit 2
    }
}

If (Test-Path -Path $KioskDir) {
    # Removing changes to default user hive by reading the restore file and resetting all configured registry values to their previous values.
    If (Test-Path -Path $RegKeysRestoreFile) {
        $RegKeys = Import-Csv -Path $RegKeysRestoreFile

        Write-Log -EventId 10 -EntryType Information -Message "Restoring registry keys to default."
        Write-Log -EventId 11 -EntryType Information -Message "Loading Default User Hive and updated registry values."
        Start-Process -FilePath "REG.exe" -ArgumentList "LOAD", "HKLM\Default", "$env:SystemDrive\Users\default\ntuser.dat" -Wait

        ForEach ($entry in $RegKeys) {
            #reset from previous values
            $Key = $null
            $Value = $null
            $Type = $null
            $Data = $null
            #set values
            $Key = $Entry.Key
            $Value = $Entry.Value
            $Type = $Entry.Type
            $Data = $Entry.Data

            If ($Key -like 'HKCU\*') {
                $Key = $Key.Replace("HKCU\","HKLM\Default\")
            }

            If ($null -ne $Data -and $Data -ne '') {
                # Restore the value to the original
                Start-Process -FilePath "REG.exe" -ArgumentList "ADD `"$Key`" /v $Value /t $Type /d `"$Data`" /f" -wait
            }
            Else {
                # Delete the value since it didn't exist.
                Start-Process -FilePath "REG.exe" -ArgumentList "DELETE `"$Key`" /v $Value /f" -wait -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log -EventId 12 -EntryType Information -Message "Unloading Default User Hive."
        $HiveUnloadResult = Start-Process -FilePath "REG.exe" -ArgumentList "UNLOAD", "HKLM\Default" -Wait -PassThru -NoNewWindow
        $ExitCode = $HiveUnloadResult.ExitCode
        If ($ExitCode -ne 0) {
            # sometimes the registry doesn't unload properly so we have to perform powershell garbage collection first.
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 5
            $HiveUnloadResult = Start-Process -FilePath "REG.exe" -ArgumentList "UNLOAD", "HKLM\Default" -Wait
            $ExitCode = $HiveUnloadResult.ExitCode
        }
        If ($ExitCode -eq 0) {
            Write-Log -EventId 13 -EntryType Information -Message "Hive unloaded successfully."
        }
        Else {
            Write-Log -EventId 14 -EntryType Error -Message "Hive unloaded with exit code '$ExitCode'."
        }      
    }

    # Remove Applocker Configuration by clearing Applocker Policy.
    If (Test-Path -Path $AppLockerRestoreFile) {
        Write-Log -EventID 15 -EntryType Information -Message "Restoring AppLocker Policy to Default."
        Set-AppLockerPolicy -XmlPolicy $AppLockerRestoreFile
        Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
        Stop-Service -Name AppIDSvc -Force
        If ((Get-Service -Name AppIDSvc).Status -eq 'Running') {
            Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove Provisioning Packages by finding the package files in the kiosksettings directory and removing them from the OS.
    If (Test-Path -Path $ProvisioningPackagesDir) {
        Write-Log -EventID 16 -EntryType Information -Message "Removing any provisioning packages previously applied by this configuration."
        $ProvisioningPackages = Get-ChildItem -Path $ProvisioningPackagesDir -Filter '*.ppkg'
        ForEach ($Package in $ProvisioningPackages) {
            $PackageId = (Get-ProvisioningPackage -AllInstalledPackages | Where-Object {$_.PackageName -eq "$($package.BaseName)"}).PackageId
            If ($PackageId) {
                Remove-ProvisioningPackage -PackageId $PackageId
            }
        }
    }

    # Restore User Logos
    If (Test-Path -Path "$kioskDir\UserLogos") {
        Write-Log -EntryType Information -EventId 17 -Message "Restoring User Logo Files"
        Get-ChildItem -Path "$KioskDir\UserLogos" | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force
        $null = cmd /c "$ToolsDir\lgpo.exe" /t "$GPODir\Remove-computer-userlogos.txt" '2>&1'
    }

    # Remove Kiosk Settings Directory
    Write-Log -EventId 18 -EntryType Information -Message "Removing '$KioskDir' Directory"
    Remove-Item -Path $KioskDir -Recurse -Force 
}

# Remove Scheduled Tasks
Write-Log -EventId 19 -EntryType Information -Message "Removing Scheduled Tasks."
Get-ScheduledTask | Where-Object {$_.TaskName -like '(AVD Client)*'} | Unregister-ScheduledTask -Confirm:$false

# Remove Custom Start Menu Shortcut
Write-Log -EventId 20 -EntryType Information -Message "Removing Custom AVD Client Shortcuts."
$DirsShortcuts = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:SystemDrive\Users\Public\Desktop"
$linkAVD = "Azure Virtual Desktop.lnk"
ForEach ($DirShortcut in $DirsShortcuts) {
    $pathLinkAVD = Join-Path $DirShortcut -ChildPath $linkAVD
    If (Test-Path -Path $pathLinkAVD) {
        Remove-Item -Path $pathLinkAVD -Force
    }
}

# Remove Custom Start Menu
Get-ChildItem -Path "$env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Filter 'LayoutModification.*' | Remove-Item -Force

# Remove Version Registry Entry
Write-Log -EventId 21 -EntryType Information -Message "Removing Kiosk Registry Key to track install version."
If (Test-Path -Path 'HKLM:\Software\Kiosk') {
    Remove-Item -Path 'HKLM:\Software\Kiosk' -Recurse -Force
}

# Remove Keyboard Filter
If ((Get-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter).state -eq 'Enabled') {
    Write-Log -EventId 22 -EntryType Information -Message "Removing Keyboard Filter and configuration."
    & "$DirConfigurationScripts\Disable-KeyboardFilter.ps1"
    If (!$Reinstall) { Disable-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter -NoRestart }
}

If (Get-LocalUser | Where-Object {$_.Name -eq 'KioskUser0'}) {

    # Delete Kiosk User Profile if it exists. First Logoff Kiosk User.
    try {
        ## Find all sessions matching the specified username
        $sessions = quser | Where-Object {$_ -match 'kioskuser0'}
        If ($sessions) {
            ## Parse the session IDs from the output
            $sessionIds = ($sessions -split ' +')[2]
            Write-Log -EventId 23 -EntryType Information -Message "Found $(@($sessionIds).Count) user login(s) on computer."
            ## Loop through each session ID and pass each to the logoff command
            $sessionIds | ForEach-Object {
                Write-Log -EventId 24 -EntryType Information -Message "Logging off session id [$($_)]..."
                logoff $_
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No user exists') {
            Write-Host "The user is not logged in."
        } else {
            throw $_.Exception.Message
        }
    }

    Write-Log -EventId 25 -EntryType Information -Message "Deleting User Profile"
    Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq 'KioskUser0' } | Remove-CimInstance -ErrorAction SilentlyContinue
    Write-Log -EventId 26 -EntryType Information -Message "Removing 'KioskUser0' User Account."
    Remove-LocalUser -Name 'KioskUser0'
}

Write-Log -EventId 27 -EntryType Information -Message "**** Custom Kiosk Mode removed successfully ****"
Stop-Transcript