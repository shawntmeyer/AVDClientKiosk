$SoftwareName = 'Citrix Workspace App'
[String]$Script:LogDir = "$($env:SystemRoot)\Logs\Software"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Dir -Force
}

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

function Remove-RegistryValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        try {
            Write-Output "${CmdletName}: Deleting registry value '$Name' from '$Path' if it exists."
            if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop) {
                Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
                Write-Output "${CmdletName}: Deleted registry value '$Name' from '$Path'."
            }
        }
        catch {
            # Silently continue if the value doesn't exist
            Write-Output "${CmdletName}: Registry value '$Name' not found at '$Path'. Nothing to delete."
        }
    }
    End {
        Write-Output "Ending ${CmdletName}"
    }
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
Write-Output "Citrix Workspace App installation completed."
Write-Output "Removing Citrix Workspace App from startup."
Remove-RegistryValue -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "ConnectionCenter"
Write-Output "Installation Complete."
Stop-Transcript
