$AppPath = (Get-ChildItem -Path $PSScriptRoot -filter *.msix).FullName
$DependenciesPath = (Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "Dependencies") -filter *.appx).FullName

# Provision the app with dependencies
Add-AppxProvisionedPackage -Online -PackagePath $AppPath -DependencyPackagePath $DependenciesPath -SkipLicense