Param
(
    [Parameter(Mandatory = $false)]
    [string]$DeploymentType = "Install"
)

#region Initialization
[string]$SoftwareVendor = 'Microsoft'
[string]$SoftwareDisplayName = 'Visual C++ Redistributables'
[string]$SoftwareName = $SoftwareDisplayName.Replace(' ','')
[uri]$SoftwareDownloadUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
[string]$ref = 'https://docs.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170#install-the-redistributable-packages'
[string]$InstallArguments = "/install /quiet /norestart"

# Logging Configuration
[String]$Script:LogDir = "$($env:SystemRoot)\Logs\Software"
[string]$Script:LogName = $SoftwareVendor + "_" + $SoftwareName + "_" + $DeploymentType + ".log"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Dir -Force
}

#endregion

#region Supporting Functions

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

Function Remove-MSIApplications {
<#
.SYNOPSIS
    Removes all MSI applications matching the specified application name.
.DESCRIPTION
    Removes all MSI applications matching the specified application name.
    Enumerates the registry for installed applications matching the specified application name and uninstalls that application using the product code, provided the uninstall string matches "msiexec".
.PARAMETER Name
    The name of the application to uninstall. Performs a contains match on the application display name by default.
.PARAMETER Exact
    Specifies that the named application must be matched using the exact name.
.PARAMETER WildCard
    Specifies that the named application must be matched using a wildcard search.
.PARAMETER Parameters
    Overrides the default parameters specified in the XML configuration file. Uninstall default is: "REBOOT=ReallySuppress /QN".
.PARAMETER AddParameters
    Adds to the default parameters specified in the XML configuration file. Uninstall default is: "REBOOT=ReallySuppress /QN".
.PARAMETER FilterApplication
    Two-dimensional array that contains one or more (property, value, match-type) sets that should be used to filter the list of results returned by Get-InstalledApplication to only those that should be uninstalled.
    Properties that can be filtered upon: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
.PARAMETER ExcludeFromUninstall
    Two-dimensional array that contains one or more (property, value, match-type) sets that should be excluded from uninstall if found.
    Properties that can be excluded: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
.PARAMETER IncludeUpdatesAndHotfixes
    Include matches against updates and hotfixes in results.
.PARAMETER LoggingOptions
    Overrides the default logging options specified in the XML configuration file. Default options are: "/L*v".
.PARAMETER LogName
    Overrides the default log file name. The default log file name is generated from the MSI file name. If LogName does not end in .log, it will be automatically appended.
    For uninstallations, by default the product code is resolved to the DisplayName and version of the application.
.PARAMETER PassThru
    Returns ExitCode, STDOut, and STDErr output from the process.
.PARAMETER ContinueOnError
    Continue if an error occured while trying to start the processes. Default: $true.
.EXAMPLE
    Remove-MSIApplications -Name 'Adobe Flash'
    Removes all versions of software that match the name "Adobe Flash"
.EXAMPLE
    Remove-MSIApplications -Name 'Adobe'
    Removes all versions of software that match the name "Adobe"
.EXAMPLE
    Remove-MSIApplications -Name 'Java 8 Update' -FilterApplication ('Is64BitApplication', $false, 'Exact'),('Publisher', 'Oracle Corporation', 'Exact')
    Removes all versions of software that match the name "Java 8 Update" where the software is 32-bits and the publisher is "Oracle Corporation".
.EXAMPLE
    Remove-MSIApplications -Name 'Java 8 Update' -FilterApplication (,('Publisher', 'Oracle Corporation', 'Exact')) -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'Contains'))
    Removes all versions of software that match the name "Java 8 Update" and also have "Oracle Corporation" as the Publisher; however, it does not uninstall "Java 8 Update 45" of the software.
    NOTE: if only specifying a single row in the two-dimensional arrays, the array must have the extra parentheses and leading comma as in this example.
.EXAMPLE
    Remove-MSIApplications -Name 'Java 8 Update' -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'Contains'))
    Removes all versions of software that match the name "Java 8 Update"; however, it does not uninstall "Java 8 Update 45" of the software.
    NOTE: if only specifying a single row in the two-dimensional array, the array must have the extra parentheses and leading comma as in this example.
.EXAMPLE
    Remove-MSIApplications -Name 'Java 8 Update' -ExcludeFromUninstall
            ('Is64BitApplication', $true, 'Exact'),
            ('DisplayName', 'Java 8 Update 45', 'Exact'),
            ('DisplayName', 'Java 8 Update 4*', 'WildCard'),
            ('DisplayName', 'Java \d Update \d{3}', 'RegEx'),
            ('DisplayName', 'Java 8 Update', 'Contains')
    Removes all versions of software that match the name "Java 8 Update"; however, it does not uninstall 64-bit versions of the software, Update 45 of the software, or any Update that starts with 4.
.NOTES
    More reading on how to create arrays if having trouble with -FilterApplication or -ExcludeFromUninstall parameter: http://blogs.msdn.com/b/powershell/archive/2007/01/23/array-literals-in-powershell.aspx
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory=$false)]
        [switch]$WildCard = $false,
        [Parameter(Mandatory=$false)]
        [Alias('Arguments')]
        [ValidateNotNullorEmpty()]
        [string]$Parameters,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$AddParameters,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [array]$FilterApplication = @(@()),
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [array]$ExcludeFromUninstall = @(@()),
        [Parameter(Mandatory=$false)]
        [switch]$IncludeUpdatesAndHotfixes = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]$LoggingOptions,
        [Parameter(Mandatory=$false)]
        [Alias('LogName')]
        [string]$private:LogName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [switch]$PassThru = $false,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "Starting ${CmdLetName} with the following parameters: $PSBoundParameters"
    }
    Process {
        ## Build the hashtable with the options that will be passed to Get-InstalledApplication using splatting
        [hashtable]$GetInstalledApplicationSplat = @{ Name = $name }
        If ($Exact) { $GetInstalledApplicationSplat.Add( 'Exact', $Exact) }
        ElseIf ($WildCard) { $GetInstalledApplicationSplat.Add( 'WildCard', $WildCard) }
        If ($IncludeUpdatesAndHotfixes) { $GetInstalledApplicationSplat.Add( 'IncludeUpdatesAndHotfixes', $IncludeUpdatesAndHotfixes) }

        [psobject[]]$installedApplications = Get-InstalledApplication @GetInstalledApplicationSplat

        Write-Verbose "${CmdLetName}: Found [$($installedApplications.Count)] application(s) that matched the specified criteria [$Name]."

        ## Filter the results from Get-InstalledApplication
        [Collections.ArrayList]$removeMSIApplications = New-Object -TypeName 'System.Collections.ArrayList'
        If (($null -ne $installedApplications) -and ($installedApplications.Count)) {
            ForEach ($installedApplication in $installedApplications) {
                If ([string]::IsNullOrEmpty($installedApplication.ProductCode)) {
                    Write-Warning "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName)] because unable to discover MSI ProductCode from application's registry Uninstall subkey [$($installedApplication.UninstallSubkey)]."
                    Continue
                }

                #  Filter the results from Get-InstalledApplication to only those that should be uninstalled
                If (($null -ne $FilterApplication) -and ($FilterApplication.Count)) {
                    Write-Verbose "${CmdletName}: Filter the results to only those that should be uninstalled as specified in parameter [-FilterApplication]."
                    [boolean]$addAppToRemoveList = $false
                    ForEach ($Filter in $FilterApplication) {
                        If ($Filter[2] -eq 'RegEx') {
                            If ($installedApplication.($Filter[0]) -match $Filter[1]) {
                                [boolean]$addAppToRemoveList = $true
                                Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of regex match against [-FilterApplication] criteria."
                            }
                        }
                        ElseIf ($Filter[2] -eq 'Contains') {
                            If ($installedApplication.($Filter[0]) -match [regex]::Escape($Filter[1])) {
                                [boolean]$addAppToRemoveList = $true
                                Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of contains match against [-FilterApplication] criteria." 
                            }
                        }
                        ElseIf ($Filter[2] -eq 'WildCard') {
                            If ($installedApplication.($Filter[0]) -like $Filter[1]) {
                                [boolean]$addAppToRemoveList = $true
                                Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of wildcard match against [-FilterApplication] criteria." 
                            }
                        }
                        ElseIf ($Filter[2] -eq 'Exact') {
                            If ($installedApplication.($Filter[0]) -eq $Filter[1]) {
                                [boolean]$addAppToRemoveList = $true
                                Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of exact match against [-FilterApplication] criteria." 
                            }
                        }
                    }
                }
                Else {
                    [boolean]$addAppToRemoveList = $true
                }

                #  Filter the results from Get-InstalledApplication to remove those that should never be uninstalled
                If (($null -ne $ExcludeFromUninstall) -and ($ExcludeFromUninstall.Count)) {
                    ForEach ($Exclude in $ExcludeFromUninstall) {
                        If ($Exclude[2] -eq 'RegEx') {
                            If ($installedApplication.($Exclude[0]) -match $Exclude[1]) {
                                [boolean]$addAppToRemoveList = $false
                                Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of regex match against [-ExcludeFromUninstall] criteria." 
                            }
                        }
                        ElseIf ($Exclude[2] -eq 'Contains') {
                            If ($installedApplication.($Exclude[0]) -match [regex]::Escape($Exclude[1])) {
                                [boolean]$addAppToRemoveList = $false
                                Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of contains match against [-ExcludeFromUninstall] criteria." 
                            }
                        }
                        ElseIf ($Exclude[2] -eq 'WildCard') {
                            If ($installedApplication.($Exclude[0]) -like $Exclude[1]) {
                                [boolean]$addAppToRemoveList = $false
                                Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of wildcard match against [-ExcludeFromUninstall] criteria." 
                            }
                        }
                        ElseIf ($Exclude[2] -eq 'Exact') {
                            If ($installedApplication.($Exclude[0]) -eq $Exclude[1]) {
                                [boolean]$addAppToRemoveList = $false
                                Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of exact match against [-ExcludeFromUninstall] criteria." 
                            }
                        }
                    }
                }

                If ($addAppToRemoveList) {
                    Write-Verbose "${CmdletName}: Adding application to list for removal: [$($installedApplication.DisplayName) $($installedApplication.Version)]." 
                    $removeMSIApplications.Add($installedApplication)
                }
            }
        }

        ## Build the hashtable with the options that will be passed to Execute-MSI using splatting
        [hashtable]$ExecuteMSISplat =  @{
            Action = 'Uninstall'
            Path = ''
            ContinueOnError = $ContinueOnError
        }
        If ($Parameters) { $ExecuteMSISplat.Add( 'Parameters', $Parameters) }
        ElseIf ($AddParameters) { $ExecuteMSISplat.Add( 'AddParameters', $AddParameters) }
        If ($LoggingOptions) { $ExecuteMSISplat.Add( 'LoggingOptions', $LoggingOptions) }
        If ($LogName) { $ExecuteMSISplat.Add( 'LogName', $LogName) }
        If ($PassThru) { $ExecuteMSISplat.Add( 'PassThru', $PassThru) }
        If ($IncludeUpdatesAndHotfixes) { $ExecuteMSISplat.Add( 'IncludeUpdatesAndHotfixes', $IncludeUpdatesAndHotfixes) }

        If (($null -ne $removeMSIApplications) -and ($removeMSIApplications.Count)) {
            ForEach ($removeMSIApplication in $removeMSIApplications) {
                Write-Verbose "${CmdletName}: Remove application [$($removeMSIApplication.DisplayName) $($removeMSIApplication.Version)]." 
                $ExecuteMSISplat.Path = $removeMSIApplication.ProductCode
                If ($PassThru) {
                    [psobject[]]$ExecuteResults += Execute-MSI @ExecuteMSISplat
                }
                Else {
                    Execute-MSI @ExecuteMSISplat
                }
            }
        }
        Else {
            Write-Log -Message 'No applications found for removal. Continue...' 
        }
    }
    End {
        If ($PassThru) { Write-Output -InputObject $ExecuteResults }
        Write-Verbose "Ending ${CmdletName}."
    }
}

#endregion

## MAIN
Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
If ($DeploymentType -ne 'UnInstall') {
    Write-Output "Retrieving latest $SoftwareDisplayName from Internet."
    $pathExe = Get-InternetFile -url $SoftwareDownloadUrl -OutputDirectory $env:Temp
    If (-not $pathExe) {
        $pathExe = (Get-ChildItem -Path $PSScriptRoot -File -Filter '*.exe').FullName
    }

    Write-Output "Starting '$SoftwareDisplayName' installation and configuration in accordance with:"
    Write-Output "     '$ref'."      
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
    Remove-MSIApplications -Name $SoftwareDisplayName -verbose
}

Stop-Transcript