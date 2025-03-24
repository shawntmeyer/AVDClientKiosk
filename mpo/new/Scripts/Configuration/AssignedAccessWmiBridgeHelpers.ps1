function Get-AssignedAccessCspBridgeWmi {
    $NameSpace = "root\cimv2\mdm\dmmap"
    $Class = "MDM_AssignedAccess"
    return Get-CimInstance -Namespace $NameSpace -ClassName $Class
}

function Set-ShellLauncherConfiguration {
    param (
        [Parameter(Mandatory=$True)]
        [String] $FilePath
    )

    $Xml = Get-Content -Path $FilePath
    $EscapedXml = [System.Security.SecurityElement]::Escape($Xml)
    $AssignedAccessCsp = Get-AssignedAccessCspBridgeWmi
    $AssignedAccessCsp.ShellLauncher = $EscapedXml
    Set-CimInstance -CimInstance $AssignedAccessCsp
    
    # get a new instance and print the value
    (Get-AssignedAccessCspBridgeWmi).ShellLauncher
}

function Clear-ShellLauncherConfiguration {
    $AssignedAccessCsp = Get-AssignedAccessCspBridgeWmi
    $AssignedAccessCsp.ShellLauncher = $NULL
    Set-CimInstance -CimInstance $AssignedAccessCsp
}

function Get-ShellLauncherConfiguration {
    (Get-AssignedAccessCspBridgeWmi).ShellLauncher
}

function Get-MultiAppKioskConfiguration {
    (Get-AssignedAccessCspBridgeWmi).Configuration
}

function Set-MultiAppKioskConfiguration {
    param (
        [Parameter(Mandatory=$True)]
        [string] $FilePath
    )

    $Xml = Get-Content -Path $FilePath
    $AssignedAccessCsp = Get-AssignedAccessCspBridgeWmi
    $EncodedXml = [System.Net.WebUtility]::HtmlEncode($Xml)
    $AssignedAccessCsp.Configuration = $EncodedXml
    Set-CimInstance -CimInstance $AssignedAccessCsp
    (Get-AssignedAccessCspBridgeWmi).Configuration
}

function Clear-MultiAppKioskConfiguration {
    $AssignedAccessCsp = Get-AssignedAccessCspBridgeWmi
    $AssignedAccessCsp.Configuration = $NULL
    Set-CimInstance -CimInstance $AssignedAccessCsp
}