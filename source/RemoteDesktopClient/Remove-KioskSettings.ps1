[CmdletBinding()]
param (
    [string]$EventLog = 'Application',
    [string]$EventSource = 'Remote Desktop Kiosk',
    [switch]$Reinstall
)

#region Set Variables
$script:FullName = $MyInvocation.MyCommand.Path
$script:Dir = Split-Path $script:FullName
$DirGPOs = "$Script:Dir\gposettings"
$DirTools = "$Script:Dir\Tools"
$DirKiosk = "$env:SystemDrive\KioskSettings"
$DirProvisioningPackages = "$DirKiosk\ProvisioningPackages"
$FileRegValuesRestore = "$DirKiosk\RegKeyRestore.csv"
$FileAppLockerRestore = "$DirKiosk\ApplockerPolicy.xml"

#endregion Set Variables

#region Restart Script in 64-bit powershell if necessary

If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    $scriptArguments = $null
    Try {
        foreach ($k in $PSBoundParameters.keys) {
            switch ($PSBoundParameters[$k].GetType().Name) {
                "SwitchParameter" { if ($PSBoundParameters[$k].IsPresent) { $scriptArguments += "-$k " } }
                "String" { $scriptArguments += "-$k `"$($PSBoundParameters[$k])`" " }
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

#region Initialization and Logging

$Functions = Get-ChildItem -Path $DirFunctions -Filter '*.ps1'
ForEach ($Function in $Functions) {
    . "$($Function.FullName)"
}

New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction SilentlyContinue

Write-Log -EventLog $EventLog -EventSource $EventSource -EntryType Information -EventId 5 -Message "Executing '$Script:FullName'."

#endregion Initialization and Logging

#region Main Script

# Removing Embedded Shells Configuration

If (Get-AssignedAccessShellLauncher) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 6 -EntryType Information -Message "Removing Shell Launcher settings via WMI Bridge."
    Clear-AssignedAccessShellLauncher
}

If (Get-AssignedAccessConfiguration) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 6 -EntryType Information -Message "Removing Multi-App Kiosk Configuration via WMI Bridge."
    Clear-AssignedAccessConfiguration
}

# Removing Non-Administrators Local GPO.
$DirNonAdminsGPO = "$env:SystemRoot\System32\GroupPolicyUsers\S-1-5-32-545"
If (Test-Path -Path $DirNonAdminsGPO) {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 7 -EntryType Information -Message "Deleting Non-Administrators local group policy object and forcing GPUpdate."
    Remove-Item -Path $DirNonAdminsGPO -Recurse -Force -ErrorAction SilentlyContinue
    If (!(Test-Path -Path $DirNonAdminsGPO)) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 8 -EntryType Information -Message "Non-Administrators Local GPO removed successfully."
        Start-Process -FilePath "gpupdate.exe" -ArgumentList "/Force" -Wait -ErrorAction SilentlyContinue
    }
    Else {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 9 -EntryType Error -Message "Non-Administrators Local GPO folder was not removed successfully."
        Exit 2
    }
}

If (Test-Path -Path $DirKiosk) {
    # Removing changes to default user hive by reading the restore file and resetting all configured registry values to their previous values.
    If (Test-Path -Path $FileRegValuesRestore) {
        $RegValues = Import-Csv -Path $FileRegValuesRestore

        Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 10 -EntryType Information -Message "Restoring registry values to default."
        
        # Check if any registry keys require HKCU access before loading the hive
        $RequiresHKCU = $RegValues | Where-Object { $_.Key -like 'HKCU:*' }
        $HiveLoaded = $false
        
        If ($RequiresHKCU) {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 11 -EntryType Information -Message "Loading Default User Hive for HKCU registry operations."
            Start-Process -FilePath "REG.exe" -ArgumentList "LOAD", "HKLM\Default", "$env:SystemDrive\Users\default\ntuser.dat" -Wait
            $HiveLoaded = $true
        }

        ForEach ($RegValue in $RegValues) {
            #reset from previous values
            $Path = $null
            $Name = $null
            $PropertyType = $null
            $Value = $null
            #set values
            $Path = $RegValue.Path
            $Name = $RegValue.Name
            $PropertyType = $RegValue.PropertyType
            $Value = $RegValue.Value

            If ($Path -like 'HKCU:\*') {
                $Path = $Path.Replace("HKCU:\", "HKLM:\Default\")
            }

            If ($null -ne $Value -and $Value -ne '') {
                # Restore the value to the original
                Set-RegistryValue -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value
            }
            Else {
                # Delete the value since it didn't exist.
                Remove-RegistryValue -Path $Path -Name $Name
            }
        }
        
        If ($HiveLoaded) {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 12 -EntryType Information -Message "Unloading Default User Hive."
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
        }
        If ($ExitCode -eq 0) {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 13 -EntryType Information -Message "Hive unloaded successfully."
        }
        Else {
            Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 14 -EntryType Error -Message "Hive unloaded with exit code '$ExitCode'."
        }      
    }

    # Remove Applocker Configuration by clearing Applocker Policy.
    If (Test-Path -Path $FileAppLockerRestore) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 15 -EntryType Information -Message "Restoring AppLocker Policy to Default."
        Set-AppLockerPolicy -XmlPolicy $FileAppLockerRestore
        Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
        Stop-Service -Name AppIDSvc -Force
        If ((Get-Service -Name AppIDSvc).Status -eq 'Running') {
            Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove Provisioning Packages by finding the package files in the kiosksettings directory and removing them from the OS.
    If (Test-Path -Path $DirProvisioningPackages) {
        Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 16 -EntryType Information -Message "Removing any provisioning packages previously applied by this configuration."
        $ProvisioningPackages = Get-ChildItem -Path $DirProvisioningPackages -Filter '*.ppkg'
        ForEach ($Package in $ProvisioningPackages) {
            $PackageId = (Get-ProvisioningPackage -AllInstalledPackages | Where-Object { $_.PackageName -eq "$($package.BaseName)" }).PackageId
            If ($PackageId) {
                Remove-ProvisioningPackage -PackageId $PackageId
            }
        }
    }

    # Restore User Logos
    If (Test-Path -Path "$DirKiosk\UserLogos") {
        Write-Log -EntryType Information -EventId 17 -Message "Restoring User Logo Files"
        Get-ChildItem -Path "$DirKiosk\UserLogos" | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force
        $null = cmd /c "$DirTools\lgpo.exe" /t "$DirGPOs\Remove-computer-userlogos.txt" '2>&1'
    }

    # Remove Kiosk Settings Directory
    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 18 -EntryType Information -Message "Removing '$DirKiosk' Directory"
    Remove-Item -Path $DirKiosk -Recurse -Force 
}

# Remove Scheduled Tasks
Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 19 -EntryType Information -Message "Removing Scheduled Tasks."
Get-ScheduledTask | Where-Object { $_.TaskName -like '(AVD Client)*' } | Unregister-ScheduledTask -Confirm:$false

# Remove Custom Start Menu Shortcut
Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 20 -EntryType Information -Message "Removing Custom AVD Client Shortcuts."
$DirsShortcuts = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:SystemDrive\Users\Public\Desktop"
$linkAVD = "Azure Virtual Desktop.lnk"
ForEach ($DirShortcut in $DirsShortcuts) {
    $pathLinkAVD = Join-Path $DirShortcut -ChildPath $linkAVD
    If (Test-Path -Path $pathLinkAVD) {
        Remove-Item -Path $pathLinkAVD -Force
    }
}

# Remove Version Registry Entry
Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 21 -EntryType Information -Message "Removing Kiosk Registry Key to track install version."
If (Test-Path -Path 'HKLM:\Software\Kiosk') {
    Remove-Item -Path 'HKLM:\Software\Kiosk' -Recurse -Force
}

# Remove Keyboard Filter
If ((Get-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter).state -eq 'Enabled') {
    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 22 -EntryType Information -Message "Removing Keyboard Filter and configuration."
    If ($Reinstall) { Disable-KeyboardFilter -Reinstall } Else { Disable-KeyboardFilter }
}

If (Get-LocalUser | Where-Object { $_.Name -eq 'KioskUser0' }) {

    # Delete Kiosk User Profile if it exists. First Logoff Kiosk User.
    try {
        ## Find all sessions matching the specified username
        $sessions = quser | Where-Object { $_ -match 'kioskuser0' }
        If ($sessions) {
            ## Parse the session IDs from the output
            $sessionIds = ($sessions -split ' +')[2]
            Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 23 -EntryType Information -Message "Found $(@($sessionIds).Count) user login(s) on computer."
            ## Loop through each session ID and pass each to the logoff command
            $sessionIds | ForEach-Object {
                Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 24 -EntryType Information -Message "Logging off session id [$($_)]..."
                logoff $_
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No user exists') {
            Write-Host "The user is not logged in."
        }
        else {
            throw $_.Exception.Message
        }
    }

    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 25 -EntryType Information -Message "Deleting User Profile"
    Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq 'KioskUser0' } | Remove-CimInstance -ErrorAction SilentlyContinue
    Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 26 -EntryType Information -Message "Removing 'KioskUser0' User Account."
    Remove-LocalUser -Name 'KioskUser0'
}

Write-Log -EventLog $EventLog -EventSource $EventSource -EventId 27 -EntryType Information -Message "**** Custom Kiosk Mode removed successfully ****"