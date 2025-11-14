$SoftwareName = 'Amazon Workspaces'
[version]$TargetVersion = '5.30.0.5657'
$RegistrationCode = 'SLiad+EUXQ58'
$LaunchArg = "--uri `"workspaces://@$RegistrationCode`""
$URLProtocolValue = "`"$env:ProgramFiles\Amazon Web Services, Inc\Amazon Workspaces\workspaces.exe`" $LaunchArg"

# Starting Tests
$ProtocolHandler = $False
$regPath = 'Registry::HKEY_CLASSES_ROOT\evo\shell\open\command'
$defaultValue = $null
If (Test-Path $regPath) {
    $regProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($regProps.PSObject.Properties.Name -contains '(default)') {
        $defaultValue = $regProps.'(default)'
    }
    Elseif ($regProps.PSObject.Properties.Name -contains '') {
        $defaultValue = $regProps.''
    }
    If ($null -ne $defaultValue) {
        if ($defaultValue -eq $URLProtocolValue) {
            $ProtocolHandler = $True
        }
    }
}

$Shortcut = $false
If (Test-Path -Path "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\Amazon WorkSpaces\EVO.lnk") {
    $Shortcut = $True
}

$Installed = $False
$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.GetValue('DisplayName') -match $SoftwareName }
If ($null -ne [string]$registryEntry) {
    [version]$version = $registryEntry.GetValue('DisplayVersion')
    if ($version -ge $TargetVersion) {
        $Installed = $True
    }
}

If ($Installed -and $ProtocolHandler -and $Shortcut) {
    Write-Output "$SoftwareName is installed, version $version"
    Exit 0
}
Elseif ($Installed -and $ProtocolHandler -and -not $Shortcut) {
    Write-Output "$SoftwareName is installed, protocol handler is configured, but shortcut is missing"
    Exit 1
}
Elseif ($Installed -and -not $ProtocolHandler -and $Shortcut) {
    Write-Output "$SoftwareName is installed, shortcut exists, but protocol handler is not configured"
    Exit 1
}
Elseif ($Installed -and -not $ProtocolHandler -and -not $Shortcut) {
    Write-Output "$SoftwareName is installed, but both protocol handler and shortcut are missing"
    Exit 1
}
Elseif (-not $Installed -and $ProtocolHandler -and $Shortcut) {
    Write-Output "$SoftwareName is not installed, but protocol handler and shortcut exist"
    Exit 1
}
Elseif (-not $Installed -and $ProtocolHandler -and -not $Shortcut) {
    Write-Output "$SoftwareName is not installed, protocol handler exists, but shortcut is missing"
    Exit 1
}
Elseif (-not $Installed -and -not $ProtocolHandler -and $Shortcut) {
    Write-Output "$SoftwareName is not installed, shortcut exists, but protocol handler is missing"
    Exit 1
}
Else {
    Write-Output "$SoftwareName is not installed, protocol handler and shortcut are missing"
    Exit 1
}


