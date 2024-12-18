' Windows Installer utility to report the language and codepage for a package
' For use with Windows Scripting Host, CScript.exe or WScript.exe
' Copyright (c) Microsoft Corporation. All rights reserved.
' Demonstrates the access of language and codepage values                 
'
Option Explicit

Const msiOpenDatabaseModeReadOnly     = 0
Const msiOpenDatabaseModeTransact     = 1
Const ForReading = 1
Const ForWriting = 2
Const TristateFalse = 0

Const msiViewModifyInsert         = 1
Const msiViewModifyUpdate         = 2
Const msiViewModifyAssign         = 3
Const msiViewModifyReplace        = 4
Const msiViewModifyDelete         = 6

Dim argCount:argCount = Wscript.Arguments.Count
If argCount > 0 Then If InStr(1, Wscript.Arguments(0), "?", vbTextCompare) > 0 Then argCount = 0
If (argCount = 0) Then
	message = "Windows Installer utility to manage language and codepage values for a package." &_
		vbNewLine & "The package language is a summary information property that designates the" &_
		vbNewLine & " primary language and any language transforms that are available, comma delim." &_
		vbNewLine & "The ProductLanguage in the database Property table is the language that is" &_
		vbNewLine & " registered for the product and determines the language used to load resources." &_
		vbNewLine & "The codepage is the ANSI codepage of the database strings, 0 if all ASCII data," &_
		vbNewLine & " and must represent the text data to avoid loss when persisting the database." &_
		vbNewLine & "The 1st argument is the path to MSI database (installer package)" &_
		vbNewLine & "To update a value, the 2nd argument contains the keyword and the 3rd the value:" &_
		vbNewLine & "   Package  {base LangId optionally followed by list of language transforms}" &_
		vbNewLine & "   Product  {LangId of the product (could be updated by language transforms)}" &_
		vbNewLine & "   Codepage {ANSI codepage of text data (use with caution when text exists!)}" &_
		vbNewLine &_
		vbNewLine & "Copyright (C) Microsoft Corporation.  All rights reserved."
	Wscript.Echo message
	Wscript.Quit 1
End If

' Connect to Windows Installer object
On Error Resume Next
Dim installer : Set installer = Nothing
Set installer = Wscript.CreateObject("WindowsInstaller.Installer") : CheckError


' Open database
Dim databasePath:databasePath = Wscript.Arguments(0)
Dim openMode : If argCount >= 3 Then openMode = msiOpenDatabaseModeTransact Else openMode = msiOpenDatabaseModeReadOnly
Dim database : Set database = installer.OpenDatabase(databasePath, openMode) : CheckError

' Update value if supplied
If argCount >= 3 Then
	Dim value:value = Wscript.Arguments(2)
	Select Case UCase(Wscript.Arguments(1))
		Case "PACKAGE"  : SetPackageLanguage database, value
		Case "PRODUCT"  : SetProductLanguage database, value
		Case "CODEPAGE" : SetDatabaseCodepage database, value
		Case Else       : Fail "Invalid value keyword"
	End Select
	CheckError
End If

' Extract language info and compose report message
Dim message:message = "Package language = "         & PackageLanguage(database) &_
					", ProductLanguage = " & ProductLanguage(database) &_
					", Database codepage = "        & DatabaseCodepage(database)
database.Commit : CheckError  ' no effect if opened ReadOnly
Set database = nothing
Wscript.Echo message
Wscript.Quit 0

' Get language list from summary information
Function PackageLanguage(database)
	On Error Resume Next
	Dim sumInfo  : Set sumInfo = database.SummaryInformation(0) : CheckError
	Dim template : template = sumInfo.Property(7) : CheckError
	Dim iDelim:iDelim = InStr(1, template, ";", vbTextCompare)
	If iDelim = 0 Then template = "Not specified!"
	PackageLanguage = Right(template, Len(template) - iDelim)
	If Len(PackageLanguage) = 0 Then PackageLanguage = "0"
End Function

' Get ProductLanguge property from Property table
Function ProductLanguage(database)
	On Error Resume Next
	Dim view : Set view = database.OpenView("SELECT `Value` FROM `Property` WHERE `Property` = 'ProductLanguage'")
	view.Execute : CheckError
	Dim record : Set record = view.Fetch : CheckError
	If record Is Nothing Then ProductLanguage = "Not specified!" Else ProductLanguage = record.IntegerData(1)
End Function

' Get ANSI codepage of database text data
Function DatabaseCodepage(database)
	On Error Resume Next
	Dim WshShell : Set WshShell = Wscript.CreateObject("Wscript.Shell") : CheckError
	Dim tempPath:tempPath = WshShell.ExpandEnvironmentStrings("%TEMP%") : CheckError
	database.Export "_ForceCodepage", tempPath, "codepage.idt" : CheckError
	Dim fileSys : Set fileSys = CreateObject("Scripting.FileSystemObject") : CheckError
	Dim file : Set file = fileSys.OpenTextFile(tempPath & "\codepage.idt", ForReading, False, TristateFalse) : CheckError
	file.ReadLine ' skip column name record
	file.ReadLine ' skip column defn record
	DatabaseCodepage = file.ReadLine
	file.Close
	Dim iDelim:iDelim = InStr(1, DatabaseCodepage, vbTab, vbTextCompare)
	If iDelim = 0 Then Fail "Failure in codepage export file"
	DatabaseCodepage = Left(DatabaseCodepage, iDelim - 1)
	fileSys.DeleteFile(tempPath & "\codepage.idt")
End Function

' Set ProductLanguge property in Property table
Sub SetProductLanguage(database, language)
	On Error Resume Next
	If Not IsNumeric(language) Then Fail "ProductLanguage must be numeric"
	Dim view : Set view = database.OpenView("SELECT `Property`,`Value` FROM `Property`")
	view.Execute : CheckError
	Dim record : Set record = installer.CreateRecord(2)
	record.StringData(1) = "ProductLanguage"
	record.StringData(2) = CStr(language)
	view.Modify msiViewModifyAssign, record : CheckError
End Sub

' Set ANSI codepage of database text data
Sub SetDatabaseCodepage(database, codepage)
	On Error Resume Next
	If Not IsNumeric(codepage) Then Fail "Codepage must be numeric"
	Dim WshShell : Set WshShell = Wscript.CreateObject("Wscript.Shell") : CheckError
	Dim tempPath:tempPath = WshShell.ExpandEnvironmentStrings("%TEMP%") : CheckError
	Dim fileSys : Set fileSys = CreateObject("Scripting.FileSystemObject") : CheckError
	Dim file : Set file = fileSys.OpenTextFile(tempPath & "\codepage.idt", ForWriting, True, TristateFalse) : CheckError
	file.WriteLine ' dummy column name record
	file.WriteLine ' dummy column defn record
	file.WriteLine codepage & vbTab & "_ForceCodepage"
	file.Close : CheckError
	database.Import tempPath, "codepage.idt" : CheckError
	fileSys.DeleteFile(tempPath & "\codepage.idt")
End Sub     

' Set language list in summary information
Sub SetPackageLanguage(database, language)
	On Error Resume Next
	Dim sumInfo  : Set sumInfo = database.SummaryInformation(1) : CheckError
	Dim template : template = sumInfo.Property(7) : CheckError
	Dim iDelim:iDelim = InStr(1, template, ";", vbTextCompare)
	Dim platform : If iDelim = 0 Then platform = ";" Else platform = Left(template, iDelim)
	sumInfo.Property(7) = platform & language
	sumInfo.Persist : CheckError
End Sub

Sub CheckError
	Dim message, errRec
	If Err = 0 Then Exit Sub
	message = Err.Source & " " & Hex(Err) & ": " & Err.Description
	If Not installer Is Nothing Then
		Set errRec = installer.LastErrorRecord
		If Not errRec Is Nothing Then message = message & vbNewLine & errRec.FormatText
	End If
	Fail message
End Sub

Sub Fail(message)
	Wscript.Echo message
	Wscript.Quit 2
End Sub

'' SIG '' Begin signature block
'' SIG '' MIIiNwYJKoZIhvcNAQcCoIIiKDCCIiQCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' P5ZR+tRLXw+tvFB7cXDc0jFoO6HhZPDQciZh+dfNY5qg
'' SIG '' ggt/MIIFBzCCA++gAwIBAgITMwAAAbRrG0O4V3NSAAAA
'' SIG '' AAABtDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJV
'' SIG '' UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
'' SIG '' UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
'' SIG '' cmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
'' SIG '' aWduaW5nIFBDQSAyMDEwMB4XDTE3MDcxODE3NTA0MloX
'' SIG '' DTE4MDcxMDE3NTA0MlowfzELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEpMCcGA1UEAxMgTWljcm9zb2Z0IFdpbmRvd3MgS2l0
'' SIG '' cyBQdWJsaXNoZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
'' SIG '' DwAwggEKAoIBAQC6DVAuLCBjckbAsMuB89ZTZhV7pZfn
'' SIG '' g2KFfInD86O36ePIaVn6zFahQgERgATZBbuzRvvbycNm
'' SIG '' cTBozhfzz6i1J2K/cDrhKqMzLZLyqUfJlNIXuIM6D6GH
'' SIG '' 1Zdw9jP1D1cr35Hi4iCGdCqqxpIxOTYm/13J4LuoCxl4
'' SIG '' /XVFxwPHQONB4AWiJbOfcoJpMuM7jIh+fV92RUOTxbk+
'' SIG '' wi2S7dCA7h1FC+gr9iYInFKHqyxHVq06vb7RLTxpTPco
'' SIG '' A4DqTNNMLPckZYjMYlIbgkG8CUjSoZA7P6zUqweigqSg
'' SIG '' vDFnSLNFpDmnN8v9S0SQdE/11LwlLKt2fPXgawILOiM6
'' SIG '' ruULAgMBAAGjggF7MIIBdzAfBgNVHSUEGDAWBgorBgEE
'' SIG '' AYI3CgMUBggrBgEFBQcDAzAdBgNVHQ4EFgQUZ9lfS+X8
'' SIG '' hAlCNe4+O1IvvYaRvKQwUgYDVR0RBEswSaRHMEUxDTAL
'' SIG '' BgNVBAsTBE1PUFIxNDAyBgNVBAUTKzIyOTkwMytmZDZi
'' SIG '' OWU1ZC1lYjczLTQxODktYWJjMi1mN2NhY2RhMzgxYWMw
'' SIG '' HwYDVR0jBBgwFoAU5vxfe7siAFjkck619CF0IzLm76ww
'' SIG '' VgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNy
'' SIG '' b3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljQ29k
'' SIG '' U2lnUENBXzIwMTAtMDctMDYuY3JsMFoGCCsGAQUFBwEB
'' SIG '' BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNy
'' SIG '' b3NvZnQuY29tL3BraS9jZXJ0cy9NaWNDb2RTaWdQQ0Ff
'' SIG '' MjAxMC0wNy0wNi5jcnQwDAYDVR0TAQH/BAIwADANBgkq
'' SIG '' hkiG9w0BAQsFAAOCAQEAoq/AVzlL/kO91si5kz0lTxpb
'' SIG '' 5Js8Do8TlwIsmQFiHb2NQc9JBqTL+FDAcOiwnGP54l4t
'' SIG '' k6tI4t602M7PkEoPoSoACaeij/JSDPS+bsj2vYxdBeky
'' SIG '' teZh+fF0re3nenr0PqzahQnHxWnF/yh3xKv0lidMolB4
'' SIG '' Sgcyhr/eNK80Lszd9E7gmMcykfOYZXxp98c9RDdyp25J
'' SIG '' u4+UvRyGms9YuLAwadVeqi2NsAoDXWk58gvL41n8mvvd
'' SIG '' cIoFvIuRMlsJgoCqj/NvFBxllDuSdVlsymUjpkJqWaNL
'' SIG '' A0bbOzOCfF/JWqrWwYtqjeTpuDw01cMyIi9OHOSFit7K
'' SIG '' uLK1PligSDCCBnAwggRYoAMCAQICCmEMUkwAAAAAAAMw
'' SIG '' DQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMw
'' SIG '' EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
'' SIG '' b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
'' SIG '' b24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
'' SIG '' ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwNjIw
'' SIG '' NDAxN1oXDTI1MDcwNjIwNTAxN1owfjELMAkGA1UEBhMC
'' SIG '' VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
'' SIG '' B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
'' SIG '' b3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUg
'' SIG '' U2lnbmluZyBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEB
'' SIG '' BQADggEPADCCAQoCggEBAOkOZFB5Z7XE4/0JAEyelKz3
'' SIG '' VmjqRNjPxVhPqaV2fG1FutM5krSkHvn5ZYLkF9KP/USc
'' SIG '' COhlk84sVYS/fQjjLiuoQSsYt6JLbklMaxUH3tHSwoke
'' SIG '' cZTNtX9LtK8I2MyI1msXlDqTziY/7Ob+NJhX1R1dSfay
'' SIG '' Ki7VhbtZP/iQtCuDdMorsztG4/BGScEXZlTJHL0dxFVi
'' SIG '' V3L4Z7klIDTeXaallV6rKIDN1bKe5QO1Y9OyFMjByIom
'' SIG '' Cll/B+z/Du2AEjVMEqa+Ulv1ptrgiwtId9aFR9UQucbo
'' SIG '' qu6Lai0FXGDGtCpbnCMcX0XjGhQebzfLGTOAaolNo2pm
'' SIG '' Y3iT1TDPlR8CAwEAAaOCAeMwggHfMBAGCSsGAQQBgjcV
'' SIG '' AQQDAgEAMB0GA1UdDgQWBBTm/F97uyIAWORyTrX0IXQj
'' SIG '' MubvrDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
'' SIG '' BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
'' SIG '' HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
'' SIG '' HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29m
'' SIG '' dC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJB
'' SIG '' dXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBM
'' SIG '' MEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
'' SIG '' dC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEw
'' SIG '' LTA2LTIzLmNydDCBnQYDVR0gBIGVMIGSMIGPBgkrBgEE
'' SIG '' AYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cu
'' SIG '' bWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVs
'' SIG '' dC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBs
'' SIG '' AF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4A
'' SIG '' dAAuIB0wDQYJKoZIhvcNAQELBQADggIBABp071dPKXvE
'' SIG '' FoV4uFDTIvwJnayCl/g0/yosl5US5eS/z7+TyOM0qduB
'' SIG '' uNweAL7SNW+v5X95lXflAtTx69jNTh4bYaLCWiMa8Iyo
'' SIG '' YlFFZwjjPzwek/gwhRfIOUCm1w6zISnlpaFpjCKTzHSY
'' SIG '' 56FHQ/JTrMAPMGl//tIlIG1vYdPfB9XZcgAsaYZ2PVHb
'' SIG '' pjlIyTdhbQfdUxnLp9Zhwr/ig6sP4GubldZ9KFGwiUpR
'' SIG '' pJpsyLcfShoOaanX3MF+0Ulwqratu3JHYxf6ptaipobs
'' SIG '' qBBEm2O2smmJBsdGhnoYP+jFHSHVe/kCIy3FQcu/HUzI
'' SIG '' Fu+xnH/8IktJim4V46Z/dlvRU3mRhZ3V0ts9czXzPK5U
'' SIG '' slJHasCqE5XSjhHamWdeMoz7N4XR3HWFnIfGWleFwr/d
'' SIG '' DY+Mmy3rtO7PJ9O1Xmn6pBYEAackZ3PPTU+23gVWl3r3
'' SIG '' 6VJN9HcFT4XG2Avxju1CCdENduMjVngiJja+yrGMbqod
'' SIG '' 5IXaRzNij6TJkTNfcR5Ar5hlySLoQiElihwtYNk3iUGJ
'' SIG '' KhYP12E8lGhgUu/WR5mggEDuFYF3PpzgUxgaUB04lZse
'' SIG '' ZjMTJzkXeIc2zk7DX7L1PUdTtuDl2wthPSrXkizON1o+
'' SIG '' QEIxpB8QCMJWnL8kXVECnWp50hfT2sGUjgd7JXFEqwZq
'' SIG '' 5tTG3yOalnXFMYIWEDCCFgwCAQEwgZUwfjELMAkGA1UE
'' SIG '' BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
'' SIG '' BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
'' SIG '' b3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENv
'' SIG '' ZGUgU2lnbmluZyBQQ0EgMjAxMAITMwAAAbRrG0O4V3NS
'' SIG '' AAAAAAABtDANBglghkgBZQMEAgEFAKCCAQQwGQYJKoZI
'' SIG '' hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
'' SIG '' CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
'' SIG '' IACfHEUjpbb6OMsQM89w72uZFdkYNMUaoednrszUaXmz
'' SIG '' MDwGCisGAQQBgjcKAxwxLgwsZkMzSlFJejlIcHNTbGN1
'' SIG '' aXFkUEp6RWcvcGZkQ3RXRUxzd1dyQ1BUSDhqOD0wWgYK
'' SIG '' KwYBBAGCNwIBDDFMMEqgJIAiAE0AaQBjAHIAbwBzAG8A
'' SIG '' ZgB0ACAAVwBpAG4AZABvAHcAc6EigCBodHRwOi8vd3d3
'' SIG '' Lm1pY3Jvc29mdC5jb20vd2luZG93czANBgkqhkiG9w0B
'' SIG '' AQEFAASCAQArh7keLX2tEbqMk9kFeBM3RmLROw9Bs14m
'' SIG '' K+ShaUxdYdVrkl8T2kaLf3T9Rh7FAlF59sK4dmssKcw4
'' SIG '' ynF82xDm3kYOkSLMKA+4lzg48jXulLyC2hdF1/A6Rlvf
'' SIG '' ht+55/vQODTlpQhBeoqSJprmlxZJULX/rAWH107/F6zr
'' SIG '' ISmZM1KEw3h96WbEg+R+E7tgHshRDF8FMohPB9CdDg3r
'' SIG '' YVBKzfbvsBLp6P/QWRVFoCxTVrYqPwasY36CmdAq7SwT
'' SIG '' PU0d9zPP4pAaY1x1zfZ6VCCxyk6wvfDNHc2dvTEdJRqo
'' SIG '' A7kWOUiYmcFbW3s3zWR8SAR46GSUfeddqUqszBjQEmVE
'' SIG '' oYITQzCCEz8GCisGAQQBgjcDAwExghMvMIITKwYJKoZI
'' SIG '' hvcNAQcCoIITHDCCExgCAQMxDzANBglghkgBZQMEAgEF
'' SIG '' ADCCATsGCyqGSIb3DQEJEAEEoIIBKgSCASYwggEiAgEB
'' SIG '' BgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIOHH
'' SIG '' RVGUOUziwg8ZSKOnMjeTrMl/E5cqOuHAkEMsbVjuAgZa
'' SIG '' sqbuMCoYEzIwMTgwNDIxMDIyOTQ5LjE1NVowBwIBAYAC
'' SIG '' AfSggbekgbQwgbExCzAJBgNVBAYTAlVTMRMwEQYDVQQI
'' SIG '' EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
'' SIG '' HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDDAK
'' SIG '' BgNVBAsTA0FPQzEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
'' SIG '' U046QzNCMC0wRjZBLTQxMTExJTAjBgNVBAMTHE1pY3Jv
'' SIG '' c29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg7IMIIGcTCC
'' SIG '' BFmgAwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG9w0BAQsF
'' SIG '' ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
'' SIG '' bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
'' SIG '' FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
'' SIG '' TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
'' SIG '' aXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAx
'' SIG '' MjE0NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
'' SIG '' V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
'' SIG '' A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
'' SIG '' VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
'' SIG '' MDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
'' SIG '' AKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77Xxo
'' SIG '' SyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEw
'' SIG '' WbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcmgqNFDdDq
'' SIG '' 9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSm
'' SIG '' XdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKx
'' SIG '' Xf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9
'' SIG '' buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcvRLqn
'' SIG '' 9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOC
'' SIG '' AeYwggHiMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQW
'' SIG '' BBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3
'' SIG '' FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
'' SIG '' VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+ii
'' SIG '' XGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
'' SIG '' dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
'' SIG '' cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5j
'' SIG '' cmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5o
'' SIG '' dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRz
'' SIG '' L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYD
'' SIG '' VR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYI
'' SIG '' KwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
'' SIG '' bS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYB
'' SIG '' BQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBj
'' SIG '' AHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZI
'' SIG '' hvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z
'' SIG '' 66bM9TG+zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj
'' SIG '' +bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5
'' SIG '' Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgP
'' SIG '' F/UveYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8
'' SIG '' tv0E4XCfMkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/
'' SIG '' amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHim
'' SIG '' bdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl
'' SIG '' 5WTs9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua2A5H
'' SIG '' moDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/n
'' SIG '' MQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL
'' SIG '' 2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI5pgt
'' SIG '' 6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN
'' SIG '' 4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQ
'' SIG '' cdeh0sVV42neV8HR3jDA/czmTfsNv11P6Z0eGTgvvM9Y
'' SIG '' BS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkSMIIE
'' SIG '' 2DCCA8CgAwIBAgITMwAAAK2AIzdlxFojagAAAAAArTAN
'' SIG '' BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
'' SIG '' Q0EgMjAxMDAeFw0xNjA5MDcxNzU2NTVaFw0xODA5MDcx
'' SIG '' NzU2NTVaMIGxMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
'' SIG '' V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
'' SIG '' A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQwwCgYD
'' SIG '' VQQLEwNBT0MxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
'' SIG '' OkMzQjAtMEY2QS00MTExMSUwIwYDVQQDExxNaWNyb3Nv
'' SIG '' ZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG
'' SIG '' 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7bMN/mUa3Y2xVe9H
'' SIG '' Kb4oVOMVAsHLOrZaHp6MA3HM20qs541Uv16h+jUBFCL8
'' SIG '' XJPvR5qXuOpq79Hqp6oluUdc5slr07QHmgby57I0yIsY
'' SIG '' e9h1tXhpRQzXUiKMsRASqbsmWj6/RlIaOWFIC5RaeKJu
'' SIG '' qShccUGtPoNWgyQsodWp8MW+b9z27xJWpzLr6cvHqSR+
'' SIG '' UZt5+gdrtyYKAzCsqLYzukStGjeDl1crhJBoNMGAfx5R
'' SIG '' YMnVfjYKsqn5PrR+t96E95vxT6gmCOYYpioCWXHMwZf4
'' SIG '' KWJ519bOTXbP/8EVAeaTmGCR02oFiSwgAYfcED06y3as
'' SIG '' g50QCfyHDZyuXJn9pwIDAQABo4IBGzCCARcwHQYDVR0O
'' SIG '' BBYEFGQhusAvrPicxwyU5ecfyQrWvP1rMB8GA1UdIwQY
'' SIG '' MBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRP
'' SIG '' ME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
'' SIG '' bS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
'' SIG '' MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
'' SIG '' KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
'' SIG '' bS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDct
'' SIG '' MDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI
'' SIG '' KwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBABKFR7nU
'' SIG '' nZjEfGRutaq4TVOKIobcdpV1XSKPN3U8XvalbzqNGX+7
'' SIG '' 6pQ0/iCmalQ2TzRU/wADlVQm83ln7/HAGPrptzDtd/9p
'' SIG '' dNozhBEOk6+BGMclWriF1mChtGtbM6P+tIYYJNghlVvu
'' SIG '' kBXG2WPu1KTY+eR63Uuyc6wWuaDABBbvNXU7UDz5YXbc
'' SIG '' AegLH2ZQGt2qWU9Mg9jFhwRCIneoyvdNpa4akcXHHSB8
'' SIG '' IVh1U69PJbrizLhwcONaYV1crONr/IzTrDg/Yj8mYMN5
'' SIG '' ppV1/I/85i0slH0C0Rvuw3+kwdmkRiI3169/mLpe93eT
'' SIG '' XasLrxRQTulmQS856oTjF3n5XFShggNzMIICWwIBATCB
'' SIG '' 4aGBt6SBtDCBsTELMAkGA1UEBhMCVVMxEzARBgNVBAgT
'' SIG '' Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
'' SIG '' BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEMMAoG
'' SIG '' A1UECxMDQU9DMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
'' SIG '' TjpDM0IwLTBGNkEtNDExMTElMCMGA1UEAxMcTWljcm9z
'' SIG '' b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsO
'' SIG '' AwIaBQADFQCcGOYa3xsDiBddHMbHLEuar+Ew2aCBwTCB
'' SIG '' vqSBuzCBuDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
'' SIG '' c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
'' SIG '' BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEMMAoGA1UE
'' SIG '' CxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVyIE5UUyBFU046
'' SIG '' MjY2NS00QzNGLUM1REUxKzApBgNVBAMTIk1pY3Jvc29m
'' SIG '' dCBUaW1lIFNvdXJjZSBNYXN0ZXIgQ2xvY2swDQYJKoZI
'' SIG '' hvcNAQEFBQACBQDehN05MCIYDzIwMTgwNDIwMjE0MjE3
'' SIG '' WhgPMjAxODA0MjEyMTQyMTdaMHQwOgYKKwYBBAGEWQoE
'' SIG '' ATEsMCowCgIFAN6E3TkCAQAwBwIBAAICGewwBwIBAAIC
'' SIG '' FZEwCgIFAN6GLrkCAQAwNgYKKwYBBAGEWQoEAjEoMCYw
'' SIG '' DAYKKwYBBAGEWQoDAaAKMAgCAQACAxbjYKEKMAgCAQAC
'' SIG '' Ax6EgDANBgkqhkiG9w0BAQUFAAOCAQEANvgP5SJs7d2x
'' SIG '' m4xBzcTYHt6cm3IWkLkGq7IL7lcN/MJidOVNYHzQca7H
'' SIG '' 8IEE5JDhsQ/dFqQ5xu6+q6M1IUw2TweaboEYP0dPMhF8
'' SIG '' fm6mCcqrqDudEqLsk4eMq2xIqPPqOjTt6GxVD38DJupD
'' SIG '' uQWxHDZiUBdTIDLYQtVO6X8sVNLUGRgIHjsAmf/XHaTu
'' SIG '' nO110YvCOosR9FpB+ZwXMsYBmN26+sf7biOMCQdeAv5j
'' SIG '' TfMAsajz9Z8MadwBdw+dUGyZRBUTxaWtTGhYsdEcx560
'' SIG '' Ml5gHEaARTHvwHXgeAmR26RIHt9QJjaaAzCB2VbJBkh8
'' SIG '' PhKhJK4ifLTThnKfdHsZejGCAvUwggLxAgEBMIGTMHwx
'' SIG '' CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
'' SIG '' MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
'' SIG '' c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAArYAj
'' SIG '' N2XEWiNqAAAAAACtMA0GCWCGSAFlAwQCAQUAoIIBMjAa
'' SIG '' BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
'' SIG '' hvcNAQkEMSIEIK++f7Lriu7c1W7AKXnXuqIL7Ept0jHz
'' SIG '' 9cFHQ7+HoMBgMIHiBgsqhkiG9w0BCRACDDGB0jCBzzCB
'' SIG '' zDCBsQQUnBjmGt8bA4gXXRzGxyxLmq/hMNkwgZgwgYCk
'' SIG '' fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
'' SIG '' Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
'' SIG '' TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
'' SIG '' aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
'' SIG '' AK2AIzdlxFojagAAAAAArTAWBBTtb3KqIxD88rUqaLWN
'' SIG '' J9fXyvJuyDANBgkqhkiG9w0BAQsFAASCAQDFYAWh5dMT
'' SIG '' 73AJzXsLjPdwYAHGdf8/LtRdbQbQ4O1TGseFJOMLPXH3
'' SIG '' VaKKkmUdo3hPqj5ne37ko7G5AXNm1MYluEe5zDrec5ka
'' SIG '' 6e+PcsLbSfU88zhWVRuIr0b5hrSTebGCmDVVJw78RaZD
'' SIG '' W26Aw6B+eyh4olMqXVSSxaJfM0XpPGRgrNWtd6CGNXBj
'' SIG '' pp/XCubwJgfZBSEJkUSpbZ/kN/Pz5azBouxtMfwtKgd+
'' SIG '' 1d0jjKao651A5Lv/IUC3GtOGpvp3VaVPoHoIC7OQ10wj
'' SIG '' vAv7GU4Q9km2B++/Pb4SNEOZ+Y2g5vil21TV9nb/DLE7
'' SIG '' 4TR1KCHieeuPHQQP3TRFiRjm
'' SIG '' End signature block
