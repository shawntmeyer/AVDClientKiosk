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

function Wait-ForChildProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ParentProcessId,
        
        [Parameter(Mandatory = $false)]
        [string]$ProcessName = "msiexec.exe",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxWaitSeconds = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$CheckIntervalSeconds = 5,
        
        [Parameter(Mandatory = $false)]
        [string]$WaitMessage = "Waiting for child processes to complete..."
    )
    
    Write-Output "Monitoring child processes for parent PID: $ParentProcessId"
    
    # Check for child processes (with timeout)
    $waited = 0
    $foundChildProcesses = $false

    do {
        $ChildProcesses = Get-CimInstance -ClassName Win32_Process | Where-Object { 
            $_.ParentProcessId -eq $ParentProcessId -and $_.Name -eq $ProcessName 
        }
        
        if ($ChildProcesses.Count -gt 0) {
            $foundChildProcesses = $true
            Write-Output $WaitMessage
            Start-Sleep -Seconds $CheckIntervalSeconds
        }
        elseif (!$foundChildProcesses -and $waited -lt $MaxWaitSeconds) {
            # Keep checking for a bit in case child processes start later
            Start-Sleep -Seconds 1
            $waited++
        }
    } while ($ChildProcesses.Count -gt 0 -or (!$foundChildProcesses -and $waited -lt $MaxWaitSeconds))
    
    if ($foundChildProcesses) {
        Write-Output "All child processes have completed."
    } else {
        Write-Output "No child processes were found within the timeout period."
    }
}

If ($DeploymentType -ne 'Uninstall') {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ', '') + ".log"
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
    Wait-ForChildProcesses -ParentProcessId $ParentPID -ProcessName "msiexec.exe" -MaxWaitSeconds 30 -CheckIntervalSeconds 5 -WaitMessage "Waiting for Citrix Workspace App installation to complete..."
    Write-Output "Citrix Workspace App installation completed."
    Write-Output "Removing Citrix Workspace App from startup."
    Remove-RegistryValue -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "ConnectionCenter"
    Write-Output "Installation Complete."
}
Else {
    [string]$Script:LogName = "Unistall-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
    Write-Output "Starting Citrix Workspace App Installation."
    $InstallerPath = (Get-ChildItem -Path $PSScriptRoot -Filter '*.exe').FullName
    Write-Output "Found Installer: '$InstallerPath'."
    $Uninstaller = Start-Process -FilePath $InstallerPath -ArgumentList "/silent /uninstall" -PassThru
    $ParentPID = $Uinstaller.Id
    Write-Output "Process ID: $ParentPID"
    # Wait for the installation to complete
    $Uninstaller.WaitForExit()
    Wait-ForChildProcesses -ParentProcessId $ParentPID -ProcessName "msiexec.exe" -MaxWaitSeconds 30 -CheckIntervalSeconds 5 -WaitMessage "Waiting for Citrix Workspace App uninstall to complete..."
    Write-Output "Citrix Workspace App uninstall completed."
}
Stop-Transcript
