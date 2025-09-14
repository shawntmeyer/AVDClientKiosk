Param
(
    [Parameter(Mandatory = $false)]
    [string]$DeploymentType = "Install"
)

#region Initialization
[string]$SoftwareDisplayName = 'Visual C++ Redistributables'
[uri]$SoftwareDownloadUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
[string]$InstallArguments = "/install /quiet /norestart"

#endregion

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

Function Get-InstalledApplication {
    <#
    .SYNOPSIS
        Retrieves information about installed applications.
    .DESCRIPTION
        Retrieves information about installed applications by querying the registry. You can specify an application name, a product code, or both.
        Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, and application architecture.
    .PARAMETER Name
        The name of the application to retrieve information for. Performs a contains match on the application display name by default.
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name.
    .PARAMETER WildCard
        Specifies that the named application must be matched using a wildcard search.
    .PARAMETER RegEx
        Specifies that the named application must be matched using a regular expression search.
    .PARAMETER ProductCode
        The product code of the application to retrieve information for.
    .PARAMETER IncludeUpdatesAndHotfixes
        Include matches against updates and hotfixes in results.
    .EXAMPLE
        Get-InstalledApplication -Name 'Adobe Flash'
    .EXAMPLE
        Get-InstalledApplication -ProductCode '{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory=$false)]
        [switch]$WildCard = $false,
        [Parameter(Mandatory=$false)]
        [switch]$RegEx = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$ProductCode,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeUpdatesAndHotfixes
    )

    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "Starting ${CmdletName} with the following parameters: $PSBoundParameters"
        [string[]]$regKeyApplications = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    Process {
        If ($name) {
            Write-Verbose "${CmdletName}: Get information for installed Application Name(s) [$($name -join ', ')]..."
        }
        If ($productCode) {
            Write-Verbose "${CmdletName}: Get information for installed Product Code [$ProductCode]..."
        }

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
                    Catch{
                        Write-Warning "${CmdletName}: Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]."
                        Continue
                    }
                }
            }
        }
        If ($ErrorUninstallKeyPath) {
            Write-Warning "${CmdletName}: The following error(s) took place while enumerating installed applications from the registry."
        }

        $UpdatesSkippedCounter = 0
        ## Create a custom object with the desired properties for the installed applications and sanitize property details
        [psobject[]]$installedApplication = @()
        ForEach ($regKeyApp in $regKeyApplication) {
            Try {
                [string]$appDisplayName = ''
                [string]$appDisplayVersion = ''
                [string]$appPublisher = ''

                ## Bypass any updates or hotfixes
                If ((-not $IncludeUpdatesAndHotfixes) -and (($regKeyApp.DisplayName -match '(?i)kb\d+') -or ($regKeyApp.DisplayName -match 'Cumulative Update') -or ($regKeyApp.DisplayName -match 'Security Update') -or ($regKeyApp.DisplayName -match 'Hotfix'))) {
                    $UpdatesSkippedCounter += 1
                    Continue
                }

                ## Remove any control characters which may interfere with logging and creating file path names from these variables
                $appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]',''
                $appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
                $appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]',''


                ## Determine if application is a 64-bit application
                [boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }

                If ($ProductCode) {
                    ## Verify if there is a match with the product code passed to the script
                    If ($regKeyApp.PSChildName -match [regex]::Escape($productCode)) {
                        Write-Verbose "${CmdletName}:Found installed application [$appDisplayName] version [$appDisplayVersion] matching product code [$productCode]."
                        $installedApplication += New-Object -TypeName 'PSObject' -Property @{
                            UninstallSubkey = $regKeyApp.PSChildName
                            ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
                            DisplayName = $appDisplayName
                            DisplayVersion = $appDisplayVersion
                            UninstallString = $regKeyApp.UninstallString
                            InstallSource = $regKeyApp.InstallSource
                            InstallLocation = $regKeyApp.InstallLocation
                            InstallDate = $regKeyApp.InstallDate
                            Publisher = $appPublisher
                            Is64BitApplication = $Is64BitApp
                        }
                    }
                }

                If ($name) {
                    ## Verify if there is a match with the application name(s) passed to the script
                    ForEach ($application in $Name) {
                        $applicationMatched = $false
                        If ($exact) {
                            #  Check for an exact application name match
                            If ($regKeyApp.DisplayName -eq $application) {
                                $applicationMatched = $true
                                Write-Verbose "${CmdletName}: Found installed application [$appDisplayName] version [$appDisplayVersion] using exact name matching for search term [$application]."
                            }
                        }
                        ElseIf ($WildCard) {
                            #  Check for wildcard application name match
                            If ($regKeyApp.DisplayName -like $application) {
                                $applicationMatched = $true
                                Write-Verbose "${CmdletName}: Found installed application [$appDisplayName] version [$appDisplayVersion] using wildcard matching for search term [$application]."
                            }
                        }
                        ElseIf ($RegEx) {
                            #  Check for a regex application name match
                            If ($regKeyApp.DisplayName -match $application) {
                                $applicationMatched = $true
                                Write-Verbose "${CmdletName}: Found installed application [$appDisplayName] version [$appDisplayVersion] using regex matching for search term [$application]."
                            }
                        }
                        #  Check for a contains application name match
                        ElseIf ($regKeyApp.DisplayName -match [regex]::Escape($application)) {
                            $applicationMatched = $true
                            Write-Verbose "${CmdletName}: Found installed application [$appDisplayName] version [$appDisplayVersion] using contains matching for search term [$application]."
                        }

                        If ($applicationMatched) {
                            $installedApplication += New-Object -TypeName 'PSObject' -Property @{
                                UninstallSubkey = $regKeyApp.PSChildName
                                ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
                                DisplayName = $appDisplayName
                                DisplayVersion = $appDisplayVersion
                                UninstallString = $regKeyApp.UninstallString
                                InstallSource = $regKeyApp.InstallSource
                                InstallLocation = $regKeyApp.InstallLocation
                                InstallDate = $regKeyApp.InstallDate
                                Publisher = $appPublisher
                                Is64BitApplication = $Is64BitApp
                            }
                        }
                    }
                }
            }
            Catch {
                Write-Error "${CmdletName}: Failed to resolve application details from registry for [$appDisplayName]."
                Continue
            }
        }

        If (-not $IncludeUpdatesAndHotfixes) {
            ## Write to log the number of entries skipped due to them being considered updates
            If ($UpdatesSkippedCounter -eq 1) {
                Write-Verbose "${CmdletName}: Skipped 1 entry while searching, because it was considered a Microsoft update."
            } else {
                Write-Verbose "${CmdletName}: Skipped $UpdatesSkippedCounter entries while searching, because they were considered Microsoft updates."
            }
        }

        If (-not $installedApplication) {
            Write-Verbose "${CmdletName}: Found no application based on the supplied parameters."
        }

        Write-Output -InputObject $installedApplication
    }
    End {
        Write-Verbose "Ending ${CmdletName}"
    }
}

#endregion

If ($DeploymentType -ne 'UnInstall') {
    Write-Output "Retrieving latest $SoftwareDisplayName from Internet."
    $pathExe = Get-InternetFile -url $SoftwareDownloadUrl -OutputDirectory $env:Temp
    Write-Output "Starting '$SoftwareDisplayName' installation"   
    Write-Output "Installing '$SoftwareDisplayName' via cmdline:"
    Write-Output "     '$pathExe $InstallArguments'"
    $Installer = Start-Process -FilePath $pathExe -ArgumentList $InstallArguments -Wait -PassThru
    If ($($Installer.ExitCode) -eq 0) {
        Write-Output "'$SoftwareDisplayName' installed successfully."
    }
    Elseif ($($Installer.ExitCode) -eq 3010){
        Write-Output "The Installer exit code is $($Installer.ExitCode). A reboot is required."
    }
    Else {
        Write-Error "The Installer exit code is $($Installer.ExitCode)"
    }
    Write-Output "Completed '$SoftwareDisplayName' Installation."
    If ($pathExe -like "$env:Temp*") {
        Start-Sleep -Seconds 10
        Remove-Item -Path $pathExe -Force -ErrorAction SilentlyContinue
    }
}
# Uninstall
Else {
    Write-Output "Removing $SoftwareDisplayName"
    $InstalledApps = Get-InstalledApplication -Name 'Visual C++ 2022'
    ForEach($InstalledApp in $InstalledApps) {
        $ProductCode = $InstalledApp.ProductCode
        Write-Output "Removing $($InstalledApp.DisplayName) with Product Code $ProductCode"
        $uninstall = Start-Process -FilePath 'msixexec.exe' -ArgumentList "/X $($InstalledApp.ProductCode) /qn" -Wait -PassThru
        If ($Uninstall.ExitCode -eq '0' -or $Uninstall.ExitCode -eq '3010') {
            Write-Output "Uninstalled successfully"
        } Else {
            Write-Warning "$ProductCode uninstall exit code $($uninstall.ExitCode)"
        }
    }
}