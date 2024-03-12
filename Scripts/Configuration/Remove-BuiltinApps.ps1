$LogDir = "$env:SystemRoot\Logs\Configuration"
If (-not (Test-Path $env:SystemRoot\Logs)) {
    $null = New-Item -Path "$env:SystemRoot\Logs" -ItemType Directory -Force
}
If (-not (Test-Path $LogDir)) {
    $null = New-Item -Path $LogDir -ItemType Directory -Force
}
Start-Transcript -Path "$LogDir\Remove-Apps.log" -Force
Write-Output "*********************************"
Write-Output "Removing Built-In Windows Apps"
Write-Output "*********************************"
$apps = "Microsoft.3DBuilder", "Microsoft.BingWeather", "Microsoft.BingNews", "# Microsoft.DesktopAppInstaller", "Microsoft.GamingApp",`
    "Microsoft.WindowsFeedbackHub", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.HEIFImageExtension", `
    "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub", `
    "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftStickyNotes", `
    "Microsoft.MixedReality.Portal", "Microsoft.MSPaint", "Microsoft.Office.OneNote", `
    "Microsoft.OneConnect", "Microsoft.Outlook.DesktopIntegrationServices", "Microsoft.OutlookForWindows", `
    "Microsoft.Paint", "Microsoft.People", "Microsoft.Print3D", "Microsoft.ScreenSketch", `
    "Microsoft.SkypeApp", "# Microsoft.StorePurchaseApp", "Microsoft.VP9VideoExtensions", `
    "Microsoft.Wallet", "Microsoft.WebMediaExtensions", "Microsoft.WebpImageExtension", "Microsoft.Windows.Photos", `
    "Microsoft.WindowsAlarms", "Microsoft.WindowsCalculator", "Microsoft.WindowsCamera", `
    "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", `
    "Microsoft.WindowsSoundRecorder", "# Microsoft.WindowsStore", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", `
    "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider", `
    "Microsoft.XboxSpeechToTextOverlay", "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", `
    "MicrosoftCorporationII.QuickAssist", "Microsoft.Todos", "Clipchamp.Clipchamp", "Microsoft.Whiteboard", "Microsoft.PowerAutomateDesktop", `
    "Microsoft.Windows.DevHome"

$applist = $apps | Where-Object {$_ -inotlike '#*'}

$ProvisionedApps = Get-AppxProvisionedPackage -online
$InstalledApps = Get-AppxPackage -AllUsers

ForEach ($app in $applist) {

    If ($($ProvisionedApps.DisplayName) -contains $app) {
        Write-Output "Removing Provisioned AppX Package [$app]"
        Get-AppxProvisionedPackage -online | Where-Object {$_.DisplayName -eq "$app"} | Remove-AppxProvisionedPackage -online
    }

    If ($($InstalledApps.Name) -contains $app) {
        Write-Output "Uninstalling Appx Package [$app] for all users."
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq "$app" } | Remove-AppxPackage -AllUsers
    }

}
Write-Output "*********************************"
Write-Output "Removing Built-in Capabilities"
Write-Output "*********************************"
$capabilitylist = "App.Support.ContactSupport", "App.Support.QuickAssist"

ForEach ($capability in $capabilitylist) {
    $InstalledCapability = $null
    $InstalledCapability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "$capability*" -and $_.State -ne "NotPresent" }
    If ($InstalledCapability) {
        Write-Output "Removing [$Capability]"
        $InstalledCapability | Remove-WindowsCapability -Online
    }
}
Stop-Transcript