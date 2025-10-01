# Intune Detection Script for NumLock Configuration
# This script checks if the NumLock registry settings have been properly configured

# Define variables
$DefaultUserHive = "C:\Users\Default\NTUSER.DAT"
$MountKey = "HKU\TempDetection"
$RegSubPath = "Control Panel\Keyboard"
$DefaultUserRegPath = "$MountKey\$RegSubPath"
$DotDefaultRegPath = "HKU\.DEFAULT\$RegSubPath"

# Initialize detection flags
$DotDefaultConfigured = $false
$DefaultUserConfigured = $false

try {
    # Check HKU\.DEFAULT configuration
    if (Test-Path $DotDefaultRegPath) {
        $dotDefaultValue = Get-ItemProperty -Path $DotDefaultRegPath -Name "InitialKeyboardIndicators" -ErrorAction SilentlyContinue
        if ($dotDefaultValue -and $dotDefaultValue.InitialKeyboardIndicators -eq 2) {
            $DotDefaultConfigured = $true
            Write-Host "HKU\.DEFAULT NumLock configuration is correct"
        }
    }
    
    # Check Default User hive configuration
    if (Test-Path $DefaultUserHive) {
        try {
            # Load the default user hive
            reg load $MountKey $DefaultUserHive 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully loaded default user hive for detection"
                
                if (Test-Path $DefaultUserRegPath) {
                    $defaultUserValue = Get-ItemProperty -Path $DefaultUserRegPath -Name "InitialKeyboardIndicators" -ErrorAction SilentlyContinue
                    if ($defaultUserValue -and $defaultUserValue.InitialKeyboardIndicators -eq 2) {
                        $DefaultUserConfigured = $true
                        Write-Host "Default User hive NumLock configuration is correct"
                    }
                }
                
                # Unload the hive
                reg unload $MountKey 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    # Retry unload with cleanup
                    [gc]::Collect()
                    [gc]::WaitForPendingFinalizers()
                    Start-Sleep -Seconds 1
                    reg unload $MountKey 2>$null | Out-Null
                }
            }
        }
        catch {
            Write-Host "Error checking default user hive: $_"
            # Attempt to unload if something went wrong
            reg unload $MountKey 2>$null | Out-Null
        }
    }
    
    # Determine overall compliance
    if ($DotDefaultConfigured -and $DefaultUserConfigured) {
        Write-Host "NumLock configuration detected successfully - both HKU\.DEFAULT and Default User hive are configured"
        exit 0
    }
    elseif ($DotDefaultConfigured -and -not (Test-Path $DefaultUserHive)) {
        Write-Host "NumLock configuration detected successfully - HKU\.DEFAULT configured and no Default User hive present"
        exit 0
    }
    else {
        Write-Host "NumLock configuration not detected or incomplete"
        Write-Host "HKU\.DEFAULT configured: $DotDefaultConfigured"
        Write-Host "Default User hive configured: $DefaultUserConfigured"
        exit 1
    }
}
catch {
    Write-Host "Error during NumLock detection: $_"
    exit 1
}