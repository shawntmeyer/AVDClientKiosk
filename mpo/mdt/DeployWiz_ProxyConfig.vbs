' // ***************************************************************************
' // 
' // Copyright (c) Microsoft Corporation.  All rights reserved.
' // 
' // Microsoft Deployment Toolkit Solution Accelerator
' //
' // File:      DeployWiz_Initialization.vbs
' // 
' // Version:   6.3.8456.1000
' // 
' // Purpose:   Main Client Deployment Wizard Initialization routines
' // 
' // ***************************************************************************


Option Explicit

Function InitializeProxyConfig

	PTRadio3.click
	ServerAddress.disabled = true
	ScriptUrl.disabled = false
	ScriptUrl.value = "http://op_autopac.corp.nsa.gov/autopac/internet.pac"

End Function

Function ValidateProxyConfig

	ValidateProxyConfig = False

	If PKRadio1.checked then

		ServerAddress.disabled = true
		ScriptUrl.disabled = true

		BlankServerAddress.style.display = "none"
		InvalidServerAddress.style.display = "none"
		BlankScriptUrl.style.display = "none"
		InvalidScriptUrl.style.display = "none"

		ProxyServerAddress.value = ""
		ProxyScriptUrl.value = ""

		ValidateProxyConfig = True


	ElseIf PKRadio2.checked then

		ServerAddress.disabled = false
		ScriptUrl.disabled = true

		BlankScriptUrl.style.display = "none"
		InvalidScriptUrl.style.display = "none"

		' Make sure the server address is valid

		If ServerAddress.value = "" then
			BlankServerAddress.style.display = "inline"
			InvalidServerAddress.style.display = "none"
		ElseIf IsEmpty(GetProxyAddress(ServerAddress.value)) then
			BlankServerAddress.style.display = "none"
			InvalidServerAddress.style.display = "inline"
		Else
			BlankServerAddress.style.display = "none"
			InvalidServerAddress.style.display = "none"
			ProxyServerAddress.value = GetProxyAddress(ServerAddress.value)
			ProxyScriptUrl.value = ""
			ValidateProxyConfig = True
		End if

	Else

		ServerAddress.disabled = true
		ScriptUrl.disabled = false

		BlankServerAddress.style.display = "none"
		InvalidServerAddress.style.display = "none"

		' Make sure the script url is valid

		If ScriptUrl.value = "" then
			BlankScriptUrl.style.display = "inline"
			InvalidScriptUrl.style.display = "none"
		ElseIf IsEmpty(GetProxyScriptUrl(ScriptUrl.value)) then
			BlankScriptUrl.style.display = "none"
			InvalidScriptUrl.style.display = "inline"
		Else
			BlankScriptUrl.style.display = "none"
			InvalidScriptUrl.style.display = "none"
			ProxyServerAddress.value = ""
			ProxyScriptUrl.value = GetProxyScriptUrl(ScriptUrl.value)
			ValidateProxyConfig = True
		End if

	End if

End Function

Function GetProxyAddress(proxyAddress)
	Dim regex, isMatch
	Set regex = New RegExp

	regex.Pattern = "^(?:(?:http|https|socks5)://)?(?:\w+:\w+@)?(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d{2,5})$"
	regex.IgnoreCase = True
	regex.Global = False

	isMatch = regex.Test(proxyAddress)
	if isMatch = true then
		GetProxyAddress = proxyAddress
	Else
		GetProxyAddress = ""
	End if 
End function

Function GetProxyScriptUrl(proxyScriptUrl)
	Dim regex, isMatch
	Set regex = New RegExp

	regex.Pattern = "^https?:\/\/[^\s\/$.?#].[^\s]*\.pac$"
	regex.IgnoreCase = True
	regex.Global = False

	isMatch = regex.Test(proxyScriptUrl)
	if isMatch = true then
		GetProxyScriptUrl = proxyScriptUrl
	Else
		GetProxyScriptUrl = ""
	End if 
End Function

Function AssignProxyConfig
	if not IsEmpty(ProxyServerAddress.value) then
		oEnvironment.Item("ProxyServerAddress") = ProxyServerAddress.value
	ElseIf not IsEmpty(ProxyScriptUrl.value) then
		oEnvironment.Item("ProxyScriptUrl") = ProxyScriptUrl.value
	End If
End Function


