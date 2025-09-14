Param
(
    [Parameter(Mandatory = $false)]
    [string]$DeploymentType = "Install"
)

#region Initialization

$SoftwareName = 'Windows App'
$Url = 'https://go.microsoft.com/fwlink/?linkid=2262633'
$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Args = $null

[String]$Script:LogDir = "$($env:SystemRoot)\Logs\Software"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Dir -Force | Out-Null
}

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

If ($DeploymentType -ne "Uninstall") {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path "$env:WinDir\Logs" -ChildPath $Script:LogName) -Force
    $AppPath = (Get-ChildItem -Path $PSScriptRoot -filter *.msix).FullName
    If (-not (Test-Path -Path $AppPath)) {
        Write-Output "Windows App MSIX package not found in $PSScriptRoot"
        Write-Output "Attempting to download from '$Url'"
        $tempDir = Join-Path -Path $env:Temp -ChildPath "$($Script:Name)"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        $AppPath = Join-Path -Path $env:Temp -ChildPath 'WindowsApp.msix'
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $AppPath -UseBasicParsing
        If (Test-Path -Path $AppPath) {
            Write-Output "Windows App MSIX package downloaded to: $AppPath"
        }
        else {
            Write-Error "Windows App MSIX package not found"
            Exit 1
        }
    }
    Else {
        Write-Output "Windows App MSIX package found in $PSScriptRoot"
    }

    $DependenciesPath = (Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "Dependencies") -filter *.appx).FullName

    # Provision the app with dependencies
    Add-AppxProvisionedPackage -Online -PackagePath $AppPath -DependencyPackagePath $DependenciesPath -SkipLicense
    if ($tempDir -and (Test-Path -Path $tempDir)) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Else {
    [string]$Script:LogName = "Uninstall" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path "$env:WinDir\Logs" -ChildPath $Script:LogName) -Force
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "MicrosoftCorporationII.Windows365" } | Remove-AppxProvisionedPackage -Online
}

Stop-Transcript