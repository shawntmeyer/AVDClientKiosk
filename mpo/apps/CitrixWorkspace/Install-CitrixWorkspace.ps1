Param (
    [string]$DeploymentType = 'Install'
)
#region Initialization
$SoftwareName = 'Citrix Workspace App'
$Url = 'https://downloads.citrix.com/25158/CitrixWorkspaceApp.exe?__gda__=exp=1757854643~acl=/*~hmac=c7423a8aa0defc134d16dea27d846c0c1753a1deee4e52a2d67b7b764b808856'
$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
[array]$Script:Args = @()

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
#endregion Initialization

#region Supporting Functions

Function Get-InternetFile {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [uri]$Url,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OutputDirectory,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$OutputFileName
    )

    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "Starting ${CmdletName} with the following parameters: $PSBoundParameters"
        $ProgressPreference = 'SilentlyContinue'
    }
    Process {

        $start_time = Get-Date

        If (!$OutputFileName) {
            Write-Verbose "${CmdletName}: No Output File Name specified. Trying to get file name from URL."
            If ((split-path -path $Url -leaf).Contains('.')) {

                $OutputFileName = split-path -path $url -leaf
                Write-Verbose "${CmdletName}: Url contains file name - '$OutputFileName'."
            }
            Else {
                Write-Verbose "${CmdletName}: Url does not contain file name. Trying 'Location' Response Header."
                $request = [System.Net.WebRequest]::Create($url)
                $request.AllowAutoRedirect = $false
                $response = $request.GetResponse()
                $Location = $response.GetResponseHeader("Location")
                If ((split-path $Location -leaf) -like '*.*') {
                    $OutputFileName = [System.IO.Path]::GetFileName($Location)
                    Write-Verbose "${CmdletName}: File Name from 'Location' Response Header is '$OutputFileName'."
                }
                Else {
                    Write-Verbose "${CmdletName}: No 'Location' Response Header returned. Trying 'Content-Disposition' Response Header."
                    $result = Invoke-WebRequest -Method GET -Uri $Url -UseBasicParsing
                    $contentDisposition = $result.Headers.'Content-Disposition'
                    If ($contentDisposition) {
                        $OutputFileName = $contentDisposition.Split("=")[1].Replace("`"", "")
                        Write-Verbose "${CmdletName}: File Name from 'Content-Disposition' Response Header is '$OutputFileName'."
                    }
                }
            }
        }

        If ($OutputFileName) { 
            $wc = New-Object System.Net.WebClient
            $OutputFile = Join-Path $OutputDirectory $OutputFileName
            Write-Verbose "${CmdletName}: Downloading file at '$url' to '$OutputFile'."
            Try {
                $wc.DownloadFile($url, $OutputFile)
                $time = (Get-Date).Subtract($start_time).Seconds
                
                Write-Verbose "${CmdletName}: Time taken: '$time' seconds."
                if (Test-Path -Path $outputfile) {
                    $totalSize = (Get-Item $outputfile).Length / 1MB
                    Write-Verbose "${CmdletName}: Download was successful. Final file size: '$totalsize' mb"
                    Return $OutputFile
                }
            }
            Catch {
                Write-Error "${CmdletName}: Error downloading file. Please check url."
                Return $Null
            }
        }
        Else {
            Write-Error "${CmdletName}: No OutputFileName specified. Unable to download file."
            Return $Null
        }
    }
    End {
        Write-Verbose "Ending ${CmdletName}"
    }
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
    }
    else {
        Write-Output "No child processes were found within the timeout period."
    }
}

If ($DeploymentType -ne 'Uninstall') {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path "$Env:SystemRoot\Logs" -ChildPath $Script:LogName) -Force
    Write-Output "Starting $SoftwareName Installation."
    $InstallerPath = (Get-ChildItem -Path $PSScriptRoot -Filter '*.exe').FullName
    If (-not $InstallerPath) {
        $TempDir = Join-Path -Path $env:Temp -ChildPath ($SoftwareName -Replace ' ', '')
        New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
        $InstallerPath = Get-InternetFile -Url $Url -OutputDirectory $TempDir -OutputFileName 'CitrixWorkspaceInstaller.exe'
    }
    If ($InstallerPath) {
        Write-Output "Found Installer: '$InstallerPath'."
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
        Wait-ForChildProcesses -ParentProcessId $ParentPID -ProcessName "msiexec.exe" -MaxWaitSeconds 30 -CheckIntervalSeconds 5 -WaitMessage "Waiting for $SoftwareName installation to complete..."
        Write-Output "$SoftwareName installation completed."
        Write-Output "Removing $SoftwareName from startup."
        Remove-RegistryValue -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "ConnectionCenter"
        Write-Output "Installation Complete."
    }
    Else {
        Write-Error "Citrix Workspace Installer not found."
        Exit 1
    }
    If ($TempDir) {Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue}
}
Else {
    [string]$Script:LogName = "Unistall-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path "$Env:SystemRoot\Logs" -ChildPath $Script:LogName) -Force
    Write-Output "Starting $SoftwareName Installation."
    $InstallerPath = (Get-ChildItem -Path $PSScriptRoot -Filter '*.exe').FullName
    Write-Output "Found Installer: '$InstallerPath'."
    $Uninstaller = Start-Process -FilePath $InstallerPath -ArgumentList "/silent /uninstall" -PassThru
    $ParentPID = $Uinstaller.Id
    Write-Output "Process ID: $ParentPID"
    # Wait for the installation to complete
    $Uninstaller.WaitForExit()
    Wait-ForChildProcesses -ParentProcessId $ParentPID -ProcessName "msiexec.exe" -MaxWaitSeconds 30 -CheckIntervalSeconds 5 -WaitMessage "Waiting for $SoftwareName uninstall to complete..."
    Write-Output "$SoftwareName uninstall completed."
}
Stop-Transcript