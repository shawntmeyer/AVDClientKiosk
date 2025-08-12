$URL = 'https://downloadplugins.citrix.com/ReceiverUpdates/Prod/Receiver/Win/CitrixWorkspaceApp25.3.10.69.exe'

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
$ProgressPreference = 'SilentlyContinue'

$InstallerPath = Join-Path -Path $Env:TEMP -ChildPath 'CitrixWorkspaceApp.exe'
Invoke-WebRequest -Uri $URL -OutFile $InstallerPath
# Install Citrix Workspace App silently with minimal components
$Installer = Start-Process -FilePath $InstallerPath -ArgumentList `
    "/silent", `
    "ADDLOCAL=ReceiverInside,ICA_Client,BCR_Client,USB,DesktopViewer,AM,SSON,WebHelper", `
    "AutoUpdateCheck=disabled", `
    "EnableCEIP=False", `
    "startAppProtection" `
    -PassThru
$ParentPID = $Installer.Id
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
        Write-Host "Waiting for Citrix Workspace App installation to complete..."
        Start-Sleep -Seconds 5
    } Elseif (!$foundChildProcesses -and $waited -lt $maxWait){
        Start-Sleep -Seconds 1
        $waited++
    }
} while ($ChildMsis.Count -gt 0 -or(!$foundChildProcesses -and $waited -lt $maxWait))