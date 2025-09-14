param (
    $DeploymentType = 'Install'
)
#region Initialization
$SoftwareName = 'InstallRoot'
$Url = 'https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/msi/InstallRoot_5.6x64.msi'
$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Args = @()

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

#endregion

#region Supporting Functions

Function Get-InstalledApplication {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string[]]$Name
    )

    Begin {
        [string[]]$regKeyApplications = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    Process { 
        ## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
        [psobject[]]$regKeyApplication = @()
        ForEach ($regKey in $regKeyApplications) {
            If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
                [psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
                ForEach ($UninstallKeyApp in $UninstallKeyApps) {
                    Try {
                        [psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
                        If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
                    }
                    Catch {
                        Continue
                    }
                }
            }
        }

        ## Create a custom object with the desired properties for the installed applications and sanitize property details
        [psobject[]]$installedApplication = @()
        ForEach ($regKeyApp in $regKeyApplication) {
            Try {
                [string]$appDisplayName = ''
                [string]$appDisplayVersion = ''
                [string]$appPublisher = ''

                ## Bypass any updates or hotfixes
                If (($regKeyApp.DisplayName -match '(?i)kb\d+') -or ($regKeyApp.DisplayName -match 'Cumulative Update') -or ($regKeyApp.DisplayName -match 'Security Update') -or ($regKeyApp.DisplayName -match 'Hotfix')) {
                    Continue
                }

                ## Remove any control characters which may interfere with logging and creating file path names from these variables
                $appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]', ''
                $appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]', ''
                $appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]', ''

                ## Determine if application is a 64-bit application
                [boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }

                If ($name) {
                    ## Verify if there is a match with the application name(s) passed to the script
                    ForEach ($application in $Name) {
                        $applicationMatched = $false
                        #  Check for a contains application name match
                        If ($regKeyApp.DisplayName -match [regex]::Escape($application)) {
                            $applicationMatched = $true
                        }

                        If ($applicationMatched) {
                            $installedApplication += New-Object -TypeName 'PSObject' -Property @{
                                SearchString       = $name
                                UninstallSubkey    = $regKeyApp.PSChildName
                                ProductCode        = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
                                DisplayName        = $appDisplayName
                                DisplayVersion     = $appDisplayVersion
                                UninstallString    = $regKeyApp.UninstallString
                                InstallSource      = $regKeyApp.InstallSource
                                InstallLocation    = $regKeyApp.InstallLocation
                                InstallDate        = $regKeyApp.InstallDate
                                Publisher          = $appPublisher
                                Is64BitApplication = $Is64BitApp
                            }
                        }
                    }
                }
            }
            Catch {
                Continue
            }
        }
        Write-Output -InputObject $installedApplication
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

#endregion

## MAIN
If ($DeploymentType -ne 'UnInstall') {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path (Join-Path -Path "$Env:SystemRoot\Logs" -ChildPath $Script:LogName)
    $InstalledApp = Get-InstalledApplication -Name $SoftwareName
    If ($InstalledApp -and $InstalledApp.ProductCode -ne '') {
        $ProductCode = $InstalledApp.ProductCode
        Write-Output "Removing $SoftwareName with Product Code $ProductCode"
        $uninstall = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/X $ProductCode /qn" -Wait -PassThru
        If ($Uninstall.ExitCode -eq '0' -or $Uninstall.ExitCode -eq '3010') {
            Write-Output "Uninstalled successfully"
        }
        Else {
            Write-Warning "$ProductCode uninstall exit code $($uninstall.ExitCode)"
        }
    }
    $PathMSI = (Get-ChildItem -Path $PSScriptRoot -Filter '*.msi').FullName
    If (-not $PathMSI) {
        $TempDir = Join-Path -Path $env:Temp -ChildPath ($SoftwareName -Replace ' ', '')
        New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
        $PathMsi = Get-InternetFile -Url $Url -OutputDirectory $TempDir -OutputFileName 'InstallRoot.msi'
    }
    If ($PathMSI) {
        Write-Output "Installing '$SoftwareName' via cmdline: 'msiexec /i $pathMSI /qn'"
        $Installer = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$PathMSI`" /qn" -Wait -PassThru
        If ($($Installer.ExitCode) -eq 0) {
            Write-Output "'$SoftwareName' installed successfully."
            $i = 0
            Do {
                Start-Sleep -Seconds 1
                $i++ 
            } Until ( (Get-ChildItem -Path "$env:SystemDrive\Users\Public\Desktop" -Filter 'InstallRoot*.lnk') -or ($i -eq 20) )
            Get-ChildItem -Path "$env:SystemDrive\Users\Public\Desktop" -Filter 'InstallRoot*.lnk' | Remove-Item -Force
        }
        Else {
            Write-Warning "The Installer exit code is $($Installer.ExitCode)"
        }
        Write-Output "Completed '$SoftwareName' Installation."
    }
    Else {
        Write-Error 'InstallRoot Installer Not found.'
        Exit 1
    }
    If ($TempDir) { Remove-Item -Path $TempDir -Force -Recurse -ErrorAction SilentlyContinue}
}
Else {
    [string]$Script:LogName = "Uninstall-" + ($SoftwareName -Replace ' ', '')
    Start-Transcript -Path (Join-Path -Path "$Env:SystemRoot\Logs" -ChildPath $Script:LogName)
    $InstalledApp = Get-InstalledApplication -Name $SoftwareName
    If ($InstalledApp -and $InstalledApp.ProductCode -ne '') {
        $ProductCode = $InstalledApp.ProductCode
        Write-Output "Removing $SoftwareName with Product Code $ProductCode"
        $uninstall = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/X $ProductCode /qn" -Wait -PassThru
        If ($Uninstall.ExitCode -eq '0' -or $Uninstall.ExitCode -eq '3010') {
            Write-Output "Uninstalled successfully"
        }
        Else {
            Write-Warning "$ProductCode uninstall exit code $($uninstall.ExitCode)"
        }
    }
}
Stop-Transcript