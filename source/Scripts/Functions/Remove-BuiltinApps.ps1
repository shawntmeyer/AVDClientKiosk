Function Remove-BuiltinApps {
    $apps = "Microsoft.3DBuilder", "Microsoft.BingWeather", "Microsoft.BingNews", "# Microsoft.DesktopAppInstaller", "Microsoft.GamingApp", `
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

    $applist = $apps | Where-Object { $_ -inotlike '#*' }

    $ProvisionedApps = Get-AppxProvisionedPackage -online
    $InstalledApps = Get-AppxPackage -AllUsers
    ForEach ($app in $applist) {
        If ($($ProvisionedApps.DisplayName) -contains $app) {
            Get-AppxProvisionedPackage -online | Where-Object { $_.DisplayName -eq "$app" } | Remove-AppxProvisionedPackage -online
        }

        If ($($InstalledApps.Name) -contains $app) {
            Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq "$app" } | Remove-AppxPackage -AllUsers
        }
    }
    $capabilitylist = "App.Support.ContactSupport", "App.Support.QuickAssist"
    ForEach ($capability in $capabilitylist) {
        $InstalledCapability = $null
        $InstalledCapability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "$capability*" -and $_.State -ne "NotPresent" }
        If ($InstalledCapability) {
            $InstalledCapability | Remove-WindowsCapability -Online
        }
    }
}