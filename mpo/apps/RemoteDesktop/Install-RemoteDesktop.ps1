Param
(
    [Parameter(Mandatory = $false)]
    [string]$DeploymentType = "Install"
)

#region Initialization

$SoftwareName = 'Remote Desktop'
$Url = "https://go.microsoft.com/fwlink/?linkid=2068602"
$MSIArguments = "/qn ALLUSERS=1"
$MSIPath = Join-Path -Path $env:Temp -ChildPath 'RemoteDesktop.msi'
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

[String]$Script:LogDir = "$($env:SystemRoot)\Logs\Software"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Dir -Force
}

#endregion Initialization

#region Supporting Functions
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
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory = $false)]
        [switch]$WildCard = $false,
        [Parameter(Mandatory = $false)]
        [switch]$RegEx = $false,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [string]$ProductCode,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeUpdatesAndHotfixes
    )

    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "Starting ${CmdletName} with the following parameters: $PSBoundParameters"
        [string[]]$regKeyApplications = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
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
                    Catch {
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
                $appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]', ''
                $appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]', ''
                $appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]', ''


                ## Determine if application is a 64-bit application
                [boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }

                If ($ProductCode) {
                    ## Verify if there is a match with the product code passed to the script
                    If ($regKeyApp.PSChildName -match [regex]::Escape($productCode)) {
                        Write-Verbose "${CmdletName}:Found installed application [$appDisplayName] version [$appDisplayVersion] matching product code [$productCode]."
                        $installedApplication += New-Object -TypeName 'PSObject' -Property @{
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
                Write-Error "${CmdletName}: Failed to resolve application details from registry for [$appDisplayName]."
                Continue
            }
        }

        If (-not $IncludeUpdatesAndHotfixes) {
            ## Write to log the number of entries skipped due to them being considered updates
            If ($UpdatesSkippedCounter -eq 1) {
                Write-Verbose "${CmdletName}: Skipped 1 entry while searching, because it was considered a Microsoft update."
            }
            else {
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

## MAIN

If ($DeploymentType -ne 'UnInstall') {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
    Write-Output "Retrieving latest $SoftwareName version from Internet."
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $Url -OutFile $MSIPath -UseBasicParsing        
    Write-Output "Installing '$SoftwareName' via cmdline:"
    Write-Output "     'msiexec.exe /i `"$MSIPath`" $MSIArguments'"
    $Installer = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$MSIPath`" $MSIArguments" -Wait -PassThru
    If ($($Installer.ExitCode) -eq 0) {
        Write-Output "'$SoftwareName' installed successfully."
        Remove-Item -Path $MSIPath -Force -ErrorAction SilentlyContinue
    }
    Else {
        Write-Error "The Installer exit code is $($Installer.ExitCode)"
    }
    Write-Output "Completed '$SoftwareName' Installation."

    $null = cmd /c REG.exe ADD HKLM\SOFTWARE\Microsoft\MSRDC\Policies /v AutomaticUpdates /d 0 /t REG_DWORD /f '2>&1'
} Else {
    [string]$Script:LogName = "UnInstall-" + ($SoftwareName -Replace ' ', '') + ".log"
    Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
    $Application = Get-InstalledApplication -Name $SoftwareName
    If ($Application -and $Application.ProductCode -ne '') {
        $ProductCode = $Application.ProductCode
        Write-Output "Removing $SoftwareName with Product Code $ProductCode"
        $uninstall = Start-Process -FilePath 'msixexec.exe' -ArgumentList "/X $($Application.ProductCode) /qn" -Wait -PassThru
        If ($Uninstall.ExitCode -eq '0' -or $Uninstall.ExitCode -eq '3010') {
            Write-Output "Uninstalled successfully"
        } Else {
            Write-Warning "$ProductCode uninstall exit code $($uninstall.ExitCode)"
        }
    }
}

Stop-Transcript