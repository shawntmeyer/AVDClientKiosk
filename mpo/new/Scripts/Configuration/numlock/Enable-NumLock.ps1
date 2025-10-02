# Define variables
$DefaultUserHive = "C:\Users\Default\NTUSER.DAT"
$MountKey = "HKU\TempDefault"
$RegSubPath = "Control Panel\Keyboard"
$DefaultUserRegPath = "$MountKey\$RegSubPath"
$DotDefaultRegPath = "HKU\.DEFAULT\$RegSubPath"

function Convert-RegistryPath {
    param([string]$shortPath)

    $shortPath -replace '^HKU\\', 'Registry::HKEY_USERS\' `
        -replace '^HKLM\\', 'Registry::HKEY_LOCAL_MACHINE\' `
        -replace '^HKCU\\', 'Registry::HKEY_CURRENT_USER\'
}

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
    $Path = Convert-RegistryPath -shortPath $Path
    Write-Verbose "${CmdletName}: Setting Registry Value $Path\$Name"
    # Create the registry Key(s) if necessary.
    If (!(Test-Path -Path $Path)) {
        Write-Verbose "${CmdletName}: Creating Registry Key: $Path"
        New-Item -Path $Path -Force | Out-Null
    }
    # Check for existing registry setting
    $RemoteValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    If ($RemoteValue) {
        # Get current Value
        $CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name
        Write-Verbose "${CmdletName}: Current Value of $($Path)\$($Name) : $CurrentValue"
        If ($Value -ne $CurrentValue) {
            Write-Verbose "${CmdletName}: Setting Value of $($Path)\$($Name) : $Value"
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force | Out-Null
        }
        Else {
            Write-Verbose "${CmdletName}: Value of $($Path)\$($Name) is already set to $Value"
        }           
    }
    Else {
        Write-Verbose "${CmdletName}: Setting Value of $($Path)\$($Name) : $Value"
        New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
    Start-Sleep -Milliseconds 500
}

# --- Step 1: Modify HKU\.DEFAULT ---

Set-RegistryValue -Name 'InitialKeyboardIndicators' -Path $DotDefaultRegPath -PropertyType String -Value '2'

# --- Step 2: Modify Default User Hive ---
if (Test-Path $DefaultUserHive) {
    try {
        $regLoad = Start-Process -FilePath "reg.exe" -ArgumentList 'LOAD', $MountKey, $DefaultUserHive -NoNewWindow -Wait -PassThru
        Write-Output "Loaded default user hive."
        Set-RegistryValue -Name 'InitialKeyboardIndicators' -Path $DefaultUserRegPath -PropertyType String -Value '2'
        $regUnload = Start-Process -FilePath "reg.exe" -ArgumentList 'UNLOAD', $MountKey -NoNewWindow -Wait -PassThru
        if ($regUnload.ExitCode -ne 0) {
            # Retry unload with cleanup
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 1
            $regUnload = Start-Process -FilePath "reg.exe" -ArgumentList 'UNLOAD', $MountKey -NoNewWindow -Wait -PassThru
        }
    }
    catch {
        Write-Error "Failed to modify default user hive: $_"
        # Attempt to unload if something went wrong
        $regUnload = Start-Process -FilePath "reg.exe" -ArgumentList 'UNLOAD', $MountKey -NoNewWindow -Wait -PassThru
    }
}
else {
    Write-Error "Default user hive not found at $DefaultUserHive"
}


