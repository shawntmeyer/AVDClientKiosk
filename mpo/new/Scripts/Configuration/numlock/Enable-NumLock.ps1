# Define variables
$DefaultUserHive = "C:\Users\Default\NTUSER.DAT"
$MountKey = "HKU\TempDefault"
$RegSubPath = "Control Panel\Keyboard"
$DefaultUserRegPath = "$MountKey\$RegSubPath"
$DotDefaultRegPath = "HKU\.DEFAULT\$RegSubPath"

# Function to ensure registry path exists
function Ensure-RegistryPath {
    param (
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        $parent = Split-Path $Path
        $leaf = Split-Path $Path -Leaf
        New-Item -Path $parent -Name $leaf -Force | Out-Null
        Write-Output "Created registry path: $Path"
    }
}

# --- Step 1: Modify HKU\.DEFAULT ---
try {
    Ensure-RegistryPath -Path $DotDefaultRegPath
    Set-ItemProperty -Path $DotDefaultRegPath -Name "InitialKeyboardIndicators" -Value "2" -Force
    Write-Output "Set InitialKeyboardIndicators to 2 in HKU\.DEFAULT"
}
catch {
    Write-Error "Failed to modify HKU\.DEFAULT: $_"
}

# --- Step 2: Modify Default User Hive ---
if (Test-Path $DefaultUserHive) {
    try {
        reg load $MountKey $DefaultUserHive | Out-Null
        Write-Output "Loaded default user hive."
        Ensure-RegistryPath -Path $DefaultUserRegPath
        Set-ItemProperty -Path $DefaultUserRegPath -Name "InitialKeyboardIndicators" -Value "2" -Force
        Write-Output "Set InitialKeyboardIndicators to 2 in Default User hive."
        reg unload $MountKey 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            # Retry unload with cleanup
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 1
            reg unload $MountKey 2>$null | Out-Null
        }
    }
    catch {
        Write-Error "Failed to modify default user hive: $_"
        # Attempt to unload if something went wrong
        reg unload $MountKey 2>$null | Out-Null
    }
}
else {
    Write-Error "Default user hive not found at $DefaultUserHive"
}





