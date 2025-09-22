$SoftwareName = 'Amazon Workspaces'
[version]$TargetVersion = '5.29.2.0000'
$RegistrationCode = 'SLiad+EUXQ58'
$LaunchArg = "--uri `"workspaces://@$RegistrationCode`""
$URLProtocolValue = "`"$env:ProgramFiles\Amazon Web Services, Inc\Amazon Workspaces\workspaces.exe`" $LaunchArg"

$ErrorActionPreference = 'Stop'

$regPath = 'Registry::HKEY_CLASSES_ROOT\evo\shell\open\command'
$defaultValue = $null
If (Test-Path $regPath) {
    try {
        $regProps = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($regProps.PSObject.Properties.Name -contains '(default)') {
            $defaultValue = $regProps.'(default)'
        }
        Elseif ($regProps.PSObject.Properties.Name -contains '') {
            $defaultValue = $regProps.''
        }
        If ($null -ne $defaultValue) {
            if ($defaultValue -ne $URLProtocolValue) {
                Throw "URL Protocol entry is [$DefaultValue], should be [$URLProtocolValue]."
            }
        }
    }
    catch {
        Throw "Error Accessing registry path: $_"
    }
}
Else {
    Throw "The registry path '$regPath' does not exist."
}

If (-Not(Test-Path -Path "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\Amazon WorkSpaces\EVO.lnk")) {
    Throw "Custom Start Menu shortcut not found."
}

$RegistryEntry = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.GetValue('DisplayName') -match $SoftwareName }
If (-not([string]$registryEntry)) {
    Throw "$SoftwareName is not installed."
}

[version]$version = $registryEntry.GetValue('DisplayVersion')
if (-not ($version) -or $version -lt $TargetVersion) {
    Throw "$SoftwareName version is lower than expected. Expected: $TargetVersion, Found: $version"
} Else {
    Write-Host "[$SoftwareName] version [$version] is installed"
    exit 0
}


