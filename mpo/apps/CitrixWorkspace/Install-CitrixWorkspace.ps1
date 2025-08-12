$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Args = $null

If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Try {

        foreach($k in $MyInvocation.BoundParameters.keys)
        {
            switch($MyInvocation.BoundParameters[$k].GetType().Name)
            {
                "SwitchParameter" {if($MyInvocation.BoundParameters[$k].IsPresent) { $Script:Args += "-$k " } }
                "String"          { $Script:Args += "-$k `"$($MyInvocation.BoundParameters[$k])`" " }
                "Int32"           { $Script:Args += "-$k $($MyInvocation.BoundParameters[$k]) " }
                "Boolean"         { $Script:Args += "-$k `$$($MyInvocation.BoundParameters[$k]) " }
            }
        }
        If ($Script:Args) {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`" $($Script:Args)" -Wait -NoNewWindow
        } Else {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`"" -Wait -NoNewWindow
        }
    }
    Catch {
        Throw "Failed to start 64-bit PowerShell"
    }
    Exit
}
$SoftwareName = 'Citrix Workspace App'
[String]$Script:LogDir = "$($env:SystemRoot)\Logs\Software"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Dir -Force
}

[string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ','') + ".log"
Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
Write-Output "Starting Citrix Workspace App Installation."
$InstallerPath = (Get-ChildItem -Path $PSScriptRoot -Filter '*.exe').FullName
Write-Output "Found Installer: '$InstallerPath'."
$Installer = Start-Process -FilePath $InstallerPath -ArgumentList `
    "/silent", `
    "ADDLOCAL=ReceiverInside,ICA_Client,BCR_Client,USB,DesktopViewer,AM,SSON,WebHelper", `
    "AutoUpdateCheck=disabled", `
    "EnableCEIP=False", `
    "startAppProtection" `
    -PassThru
$ParentPID = $Installer.Id
Write-Output "Process ID: $ParentPID"
# Wait for the installation to complete
$Installer.WaitForExit()
# Check for child MSI processes (with timeout)
$maxWait = 30 # seconds
$waited = 0
$foundChildProcesses = $false

# Monitor the installation process
do {
    $ChildMsis = Get-CimInstance -ClassName Win32_Process | Where-Object {$_.ParentProcessId -eq $ParentPID -and $_.Name -eq "msiexec.exe"}
    If ($ChildMsis.Count -gt 0) {
        Write-Output "Waiting for Citrix Workspace App installation to complete..."
        Start-Sleep -Seconds 5
    } Elseif (!$foundChildProcesses -and $waited -lt $maxWait){
        Start-Sleep -Seconds 1
        $waited++
    }
} while ($ChildMsis.Count -gt 0 -or(!$foundChildProcesses -and $waited -lt $maxWait))
Write-Output "Installation Complete."
Stop-Transcript
