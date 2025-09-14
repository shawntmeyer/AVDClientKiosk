$SoftwareName = 'Amazon Workspaces'
[version]$TargetVersion = '5.29.2.0000'
$URLProtocolValue = "`"$env:ProgramFiles\Amazon Web Services, Inc\Amazon Workspaces\workspaces.exe`" --uri `"//@SLiad+EUXQ58`""
$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.GetValue('DisplayName') -match $SoftwareName }

Function Get-EvoURLProtocolValue {
    param (
        $regPath = 'Registry::HKEY_CLASSES_ROOT\evo\shell\open\command'
    )
    $defaultValue = $null
    If (Test-Path $regPath) {
        try {
            $regProps = Get-ItemProperty -Path $regPath -ErrorAction Stop
            if ($regProps.PSObject.Properties.Name -contains '(default)') {
                $defaultValue = $regProps.'(default)'
            } Elseif ($regProps.PSObject.Properties.Name -contains '') {
                $defaultValue = $regProps.''
            }
        }
        catch {
            Write-Error "Error Accessing registry path: $_"
        }
    }
    Else {
        Write-Error "The registry path '$regPath' does not exist."
    }
    Return $defaultValue
}

If (Get-EvoURLProtocolValue -eq $URLProtocolValue) {
    If (([string]$registryEntry)) {

        [version]$version = $registryEntry.GetValue('DisplayVersion')
        if ($version -ge $TargetVersion) {
            Write-Host "$SoftwareName is installed"
            Write-Host "Version: $version"
            exit 0

        } else {
            Write-Host "$SoftwareName version is lower than expected. Expected: $TargetVersion, Found: $version"
            exit 1
        }
    } else {
        Write-Host "$SoftwareName isn't installed"
        exit 1
    }
} Else {
    Write-Host "Evo Protocol handler is not properly configured."
    exit 2
}


