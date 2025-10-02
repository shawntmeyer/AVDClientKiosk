# Intune Detection Script for NumLock Configuration
# This script checks if the NumLock registry settings have been properly configured

# Define variables
$DefaultUserHive = "C:\Users\Default\NTUSER.DAT"
$MountKey = "HKU\TempDetection"
$RegSubPath = "Control Panel\Keyboard"
$DefaultUserRegPath = "$MountKey\$RegSubPath"
$DotDefaultRegPath = "HKU\.DEFAULT\$RegSubPath"

Function Convert-RegistryPath {
    param([string]$shortPath)

    $shortPath -replace '^HKU\\', 'Registry::HKEY_USERS\' `
        -replace '^HKLM\\', 'Registry::HKEY_LOCAL_MACHINE\' `
        -replace '^HKCU\\', 'Registry::HKEY_CURRENT_USER\'
}

# Initialize detection flags
$DotDefaultConfigured = $false
$DefaultUserConfigured = $false

try {
    # Check HKU\.DEFAULT configuration

    $dotDefaultValue = Get-ItemProperty -Path (Convert-RegistryPath -ShortPath $DotDefaultRegPath) -Name "InitialKeyboardIndicators" -ErrorAction SilentlyContinue
    if ($dotDefaultValue -and $dotDefaultValue.InitialKeyboardIndicators -eq 2) {
        $DotDefaultConfigured = $true
        Write-Host "HKU\.DEFAULT NumLock configuration is correct"
    }
    
    # Check Default User hive configuration
    if (Test-Path $DefaultUserHive) {
        try {
            # Load the default user hive
            $regLoad = Start-Process -FilePath "reg.exe" -ArgumentList 'LOAD', $MountKey, $DefaultUserHive -NoNewWindow -Wait -PassThru
            if ($regLoad.ExitCode -eq 0) {      
                $defaultUserValue = Get-ItemProperty -Path (Convert-RegistryPath -ShortPath $DefaultUserRegPath) -Name "InitialKeyboardIndicators" -ErrorAction SilentlyContinue
                if ($defaultUserValue -and $defaultUserValue.InitialKeyboardIndicators -eq 2) {
                    $DefaultUserConfigured = $true
                    Write-Host "Default User hive NumLock configuration is correct"
                }
                
                # Unload the hive
                $regUnload = Start-Process -FilePath "reg.exe" -ArgumentList 'UNLOAD', $MountKey -NoNewWindow -Wait -PassThru
                if ($regUnload.ExitCode -ne 0) {
                    # Retry unload with cleanup
                    [gc]::Collect()
                    [gc]::WaitForPendingFinalizers()
                    Start-Sleep -Seconds 1
                    $regUnload = Start-Process -FilePath "reg.exe" -ArgumentList 'UNLOAD', $MountKey -NoNewWindow -Wait -PassThru
                }
            }
        }
        catch {
            Write-Host "Error checking default user hive: $_"
            # Attempt to unload if something went wrong
            $regUnload = Start-Process -FilePath "reg.exe" -ArgumentList 'UNLOAD', $MountKey -NoNewWindow -Wait -PassThru
        }
    }
    
    # Determine overall compliance
    if ($DotDefaultConfigured -and $DefaultUserConfigured) {
        Write-Host "NumLock configuration detected successfully - both HKU\.DEFAULT and Default User hive are configured"
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