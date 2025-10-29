Function Remove-RegistryKey {
    param (
        [Parameter(Mandatory = $true)]
        [string]$KeyPath
    )

    if (Test-Path -Path $KeyPath) {
        Remove-Item -Path $KeyPath -Recurse -Force
    }
}

Function Remove-RegistryValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    }

}

Function Set-RegistryValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$PropertyType,

        [Parameter(Mandatory = $true)]
        $Value
    )

    # Create the registry Key(s) if necessary.
    If (!(Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    # Check for existing registry setting
    $RemoteValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    If ($RemoteValue) {
        # Get current Value
        $CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name
        If ($Value -ne $CurrentValue) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force | Out-Null
        }
        Else {
        }           
    }
    Else {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
}