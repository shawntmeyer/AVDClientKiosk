Param 
(
    [string]$DeploymentType = 'Install'
)

$SoftwareName = 'DLogic DL 533N Drivers'
$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Args = $null
$Script:LogDir = Join-Path -Path "$Env:SystemRoot\Logs" -ChildPath 'Software'

If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Try {

        foreach ($k in $MyInvocation.BoundParameters.keys) {
            switch ($MyInvocation.BoundParameters[$k].GetType().Name) {
                "SwitchParameter" { if ($MyInvocation.BoundParameters[$k].IsPresent) { $Script:Args += "-$k " } }
                "String" { $Script:Args += "-$k `"$($MyInvocation.BoundParameters[$k])`" " }
                "Int32" { $Script:Args += "-$k $($MyInvocation.BoundParameters[$k]) " }
                "Boolean" { $Script:Args += "-$k `$$($MyInvocation.BoundParameters[$k]) " }
            }
        }
        If ($Script:Args) {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`" $($Script:Args)" -Wait -NoNewWindow
        }
        Else {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`"" -Wait -NoNewWindow
        }
    }
    Catch {
        Throw "Failed to start 64-bit PowerShell"
    }
    Exit
}

If (-not (Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Directory -Force | Out-Null
}

If ($DeploymentType -ne "Uninstall") {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path $Script:LogDir -ChildPath $Script:LogName) -Force
    $DriverFile = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'drivers') -Filter '*.inf'
    If ($DriverFile) {
        $infFilePath = $DriverFile.FullName
        pnputil /add-driver "$infFilePath" /install
    }
}
Else {
        [string]$Script:LogName = "Uninstall-" + ($SoftwareName -Replace ' ', '') + ".log"
        Start-Transcript -Path (Join-Path -Path $Script:LogDir -ChildPath $Script:LogName) -Force
        $OriginalFileName = 'libusb-win32_Generic_Device.inf'

        $Pkg = Get-WindowsDriver -Online | Where-Object {$_.OriginalFileName -like "*$OriginalFileName"}
        if ($Pkg) {
            $published = $pkg.PublishedName
            write-Output "Found driver package published to $published. Removing"
            pnputil /delete-driver $published /uninstall
        }
}
Stop-Transcript
