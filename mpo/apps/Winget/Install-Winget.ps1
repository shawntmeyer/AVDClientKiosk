$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Try {
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -Scope AllUsers
    $URL = 'https://aka.ms/getwinget'
    $Installer = Join-Path -Path $Env:Temp -ChildPath 'Microsoft.DesktopInstaller.msixbundle'
    Invoke-WebRequest -Uri $URL -OutFile $Installer
    Add-AppxProvisionedPackage -Online -PackagePath $Installer -SkipLicense | Out-Null
    Start-Sleep -seconds 30
    Remove-Item -Path $Installer -Force
}
Catch {
    Throw
}