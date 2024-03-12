[CmdletBinding(SupportsShouldProcess = $true)]
param (

    [Parameter(Mandatory = $false)]
    [Hashtable] $DynParameters
)

#region Initialization

$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name=[System.IO.Path]::GetFileNameWithoutExtension($Script:File)

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

[String]$Script:LogDir = "$($env:SystemRoot)\Logs\Configuration"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path "$($env:SystemRoot)\Logs" -Name Configuration -ItemType Dir -Force
}
[string]$Script:LogName = "$($Script:Name).log"
If (Test-Path "$Script:LogDir\$Script:LogName") {
    Remove-Item "$Script:LogDir\$Script:LogName" -Force
}
Start-Transcript -Path "$Script:LogDir\$Script:LogName"
#endregion

#region Functions

Function Set-BluetoothRadioStatus {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Off', 'On')]
        [string]$BluetoothStatus
    )
    If ((Get-Service bthserv).Status -eq 'Stopped') { Start-Service bthserv }
    Try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        Function Await($WinRtTask, $ResultType) {
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            $netTask.Result
        }
        [Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        [Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
        $radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
        If ($radios) {
            $bluetooth = $radios | Where-Object { $_.Kind -eq 'Bluetooth' }
        }
        If ($bluetooth) {
            [Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
            Await ($bluetooth.SetStateAsync($BluetoothStatus)) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
        }
    } Catch {
        Write-Warning "Set-BluetoothStatus function errored."
    }
}

Function Get-InternetUrl {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [uri]$Url,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$searchstring
    )
    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "${CmdletName}: Starting ${CmdletName} with the following parameters: $PSBoundParameters"
    }
    Process {

        Try {
            Write-Verbose -message "${CmdletName}: Now extracting download URL from '$Url'."
            $HTML = Invoke-WebRequest -Uri $Url -UseBasicParsing
            $Links = $HTML.Links
            $ahref = $null
            $ahref=@()
            $ahref = ($Links | Where-Object {$_.href -like "*$searchstring*"}).href
            If ($ahref.count -eq 0 -or $null -eq $ahref) {
                $ahref = ($Links | Where-Object {$_.OuterHTML -like "*$searchstring*"}).href
            }
            If ($ahref.Count -eq 1) {
                Write-Verbose -Message "${CmdletName}: Download URL = '$ahref'"
                $ahref

            }
            Elseif ($ahref.Count -gt 1) {
                Write-Verbose -Message "${CmdletName}: Download URL = '$($ahref[0])'"
                $ahref[0]
            }
        }
        Catch {
            Write-Error "${CmdletName}: Error Downloading HTML and determining link for download."
        }
    }
    End {
        Write-Verbose -Message "${CmdletName}: Ending ${CmdletName}"
    }
}

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
    }
    Process {

        $start_time = Get-Date

        If (!$OutputFileName) {
            Write-Verbose "${CmdletName}: No OutputFileName specified. Trying to get file name from URL."
            If ((split-path -path $Url -leaf).Contains('.')) {

                $OutputFileName = split-path -path $url -leaf
                Write-Verbose "${CmdletName}: Url contains file name - '$OutputFileName'."
            }
            Else {
                Write-Verbose "${CmdletName}: Url does not contain file name. Trying 'Location' Response Header."
                $request = [System.Net.WebRequest]::Create($url)
                $request.AllowAutoRedirect=$false
                $response=$request.GetResponse()
                $Location = $response.GetResponseHeader("Location")
                If ($Location) {
                    $OutputFileName = [System.IO.Path]::GetFileName($Location)
                    Write-Verbose "${CmdletName}: File Name from 'Location' Response Header is '$OutputFileName'."
                }
                Else {
                    Write-Verbose "${CmdletName}: No 'Location' Response Header returned. Trying 'Content-Disposition' Response Header."
                    $result = Invoke-WebRequest -Method GET -Uri $Url -UseBasicParsing
                    $contentDisposition = $result.Headers.'Content-Disposition'
                    If ($contentDisposition) {
                        $OutputFileName = $contentDisposition.Split("=")[1].Replace("`"","")
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

#endregion

#region Main

#Download LGPO and copy it to System32

If (!(Test-Path -Path "$env:SystemRoot\System32\LGPO.exe")) {

    $urlLGPO = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip'
    $outputDir = "$env:Temp\LGPO"
    $fileLGPODownload = Get-InternetFile -Url $urlLGPO -OutputDirectory $env:Temp
    $outputDir = "$env:Temp\LGPO"
    Expand-Archive -Path $fileLGPODownload -DestinationPath $outputDir
    Remove-Item $fileLGPODownload -Force
    $fileLGPO = (Get-ChildItem -Path $outputDir -file -Filter 'lgpo.exe' -Recurse)[0].FullName
    Write-Output "Copying `"$fileLGPO`" to System32"
    Copy-Item -Path $fileLGPO -Destination "$env:SystemRoot\System32" -Force
    Remove-Item -Path $outputDir -Recurse -Force
}
#Download the STIG GPOs
$uriSTIGs = 'https://public.cyber.mil/stigs/gpo'
$uriGPODownload = Get-InternetUrl -Url $uriSTIGs -searchstring 'GPOs'
Write-Output "Downloading STIG GPOs from `"$uriGPODownload`"."
If ($uriGPODownload) {
    $file = Get-InternetFile -url $uriGPODownload -OutputDirectory $env:TEMP
}

$OutputDir = "$env:Temp\GPOs"
If (Test-Path -Path $OutputDir) {
    Remove-Item $OutputDir -Recurse -Force
}
Expand-Archive -Path $file -DestinationPath $outputDir
Remove-Item -Path $file -Force
Write-Output "Copying ADMX and ADML files to local system."

$null = Get-ChildItem -Path "$outputDir\ADMX Templates\Microsoft" -File -Recurse -Filter '*.admx' | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$env:WINDIR\PolicyDefinitions\" -Force }
$null = Get-ChildItem -Path "$outputDir\ADMX Templates\Microsoft" -Directory -Recurse | Where-Object {$_.Name -eq 'en-us'} | Get-ChildItem -File -recurse -filter '*.adml' | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$env:WINDIR\PolicyDefinitions\en-us\" -Force }

Write-Output "Getting List of Applicable GPO folders."
$arrApplicableGPOs = Get-ChildItem -Path $outputDir | Where-Object {$_.Name -like 'DoD*Windows 10*' -or $_.Name -like 'DoD*Edge*' -or $_.Name -like 'DoD*Firewall*' -or $_.Name -like 'DoD*Internet Explorer*' -or $_.Name -like 'DoD*Defender Antivirus*'} 
[array]$arrGPOFolders = $null
ForEach ($folder in $arrApplicableGPOs.FullName) {
    $gpoFolderPath = (Get-ChildItem -Path $folder -Filter 'GPOs' -Directory).FullName
    $arrGPOFolders += $gpoFolderPath
}
ForEach ($gpoFolder in $arrGPOFolders) {
    Write-Output "Running 'LGPO.exe /g `"$gpoFolder`"'"
    $lgpo = Start-Process -FilePath "$env:SystemRoot\System32\lgpo.exe" -ArgumentList "/g `"$gpoFolder`"" -Wait -PassThru
    Write-Output "'lgpo.exe' exited with code [$($lgpo.ExitCode)]."
}

#Disable Windows PowerShell V2
Write-Output "V-220728: Disabling the PowerShell V2."
If ((Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -eq 'MicrosoftWindowsPowerShellV2Root'}).State -eq 'Enabled') {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
}

#Disable Secondary Logon Service
Write-Output "V-220732: Disabling the Secondary Logon Service."
$Service = 'SecLogon'
$Serviceobject = Get-Service | Where-Object {$_.Name -eq $Service}
If ($Serviceobject) {
    $StartType = $ServiceObject.StartType
    If ($StartType -ne 'Disabled') {
        start-process -FilePath "reg.exe" -ArgumentList "ADD HKLM\System\CurrentControlSet\Services\SecLogon /v Start /d 4 /T REG_DWORD /f" -PassThru -Wait
    }
    If ($ServiceObject.Status -ne 'Stopped') {
        Try {
            Stop-Service $Service -Force
        }
        Catch {
        }
    }
}

<# Enables DEP. If there are bitlocker encrypted volumes, bitlocker is temporarily suspended for this operation
Configure DEP to at least OptOut
V-220726 Windows 10
V-253283 Windows 11
#>
Write-Output "V-220726: Checking to see if DEP is enabled."
$nxOutput = BCDEdit /enum '{current}' | Select-string nx
if (-not($nxOutput -match "OptOut" -or $nxOutput -match "AlwaysOn")) {
    Write-Output "DEP is not enabled. Enabling."
    # Determines bitlocker encrypted volumes
    $encryptedVolumes = (Get-BitLockerVolume | Where-Object {$_.ProtectionStatus -eq 'On'}).MountPoint
    if ($encryptedVolumes.Count -gt 0) {
        Write-Log -EventId 1 -Message "Encrypted Drive Found. Suspending encryption temporarily."
        foreach ($volume in $encryptedVolumes) {
            Suspend-BitLocker -MountPoint $volume -RebootCount 0
        }
        Start-Process -Wait -FilePath 'C:\Windows\System32\bcdedit.exe' -ArgumentList '/set "{current}" nx OptOut'
        foreach ($volume in $encryptedVolumes) {
            Resume-BitLocker -MountPoint $volume
            Write-Output "Resumed Protection."
        }
    }
    else {
        Start-Process -Wait -FilePath 'C:\Windows\System32\bcdedit.exe' -ArgumentList '/set "{current}" nx OptOut'
    }
} Else {
    Write-Output "DEP is already enabled."
}

# V-220734 Bluetooth
Write-Output 'V-220734: Disabling Bluetooth Radios.'
Set-BluetoothRadioStatus -BluetoothStatus Off

Write-Output "Configuring Registry Keys that aren't policy objects."
# WN10-CC-000039
Reg.exe ADD "HKLM\SOFTWARE\Classes\batfile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f
Reg.exe ADD "HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f
Reg.exe ADD "HKLM\SOFTWARE\Classes\exefile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f
Reg.exe ADD "HKLM\SOFTWARE\Classes\mscfile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f

# CVE-2013-3900
Write-Output "CVE-2013-3900: Mitigating PE Installation risks."
Reg.exe ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -v EnableCertPaddingCheck -d 1 -t REG_DWORD -f
Reg.exe ADD "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -v EnableCertPaddingCheck -d 1 -t REG_DWORD -f

Remove-Item -Path $OutputDir -Recurse -Force
Stop-Transcript