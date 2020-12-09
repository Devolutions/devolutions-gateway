
$PackageName = "DevolutionsGateway"
$Version = '2020.3.0' # TODO: detect version
$ShortVersion = $Version.Substring(2)
$InternalVersion = "0.14.0"
$TargetArch = "x64"

$ModuleName = "DevolutionsGateway"
$ModuleVersion = '2020.3.1'

$WebClient = [System.Net.WebClient]::new()
$DownloadUrl = "https://github.com/Devolutions/devolutions-gateway/releases/download/" + `
    "v${InternalVersion}/DevolutionsGateway_windows_${InternalVersion}_x86_64.exe"

$OutputFile = "$(Get-Location)/bin/${TargetArch}/DevolutionsGateway.exe"
New-Item -Path "bin/${TargetArch}" -ItemType 'Directory' -ErrorAction 'SilentlyContinue' | Out-Null
Remove-Item $OutputFile -ErrorAction 'SilentlyContinue'
$WebClient.DownloadFile($DownloadUrl, $OutputFile)

Save-Module -Name $ModuleName -Force -RequiredVersion $ModuleVersion -Repository 'PSGallery' -Path '.'
Remove-Item -Path "${ModuleName}/${ModuleVersion}/PSGetModuleInfo.xml" -ErrorAction 'SilentlyContinue'

$WixExtensions = @('WixUtilExtension', 'WixUIExtension', 'WixFirewallExtension')
$WixExtensions += $(Join-Path $(Get-Location) 'WixUserPrivilegesExtension.dll')

$WixArgs = @($WixExtensions | ForEach-Object { @('-ext', $_) }) + @(
    "-dDGatewayPSSourceDir=${ModuleName}/${ModuleVersion}",
    "-dVersion=$ShortVersion")

$WixFiles = @('DevolutionsGateway', "DevolutionsGateway-${TargetArch}")

$HeatArgs = @('dir', "${ModuleName}/${ModuleVersion}",
    "-dr", "DGATEWAYPSROOTDIRECTORY",
    "-cg", "DGatewayPSComponentGroup",
    '-var', 'var.DGatewayPSSourceDir',
    '-nologo', '-srd', '-suid', '-sfrag', '-gg')

& 'heat.exe' $HeatArgs + @('-t', 'HeatTransform64.xslt', '-o', "${PackageName}-${TargetArch}.wxs")

$InputFiles = $WixFiles | ForEach-Object { "$_.wxs" }
$ObjectFiles = $WixFiles | ForEach-Object { "$_.wixobj" }

$Cultures = @('en-US', 'fr-FR')

foreach ($Culture in $Cultures) {
    & 'candle.exe' "-nologo" $InputFiles $WixArgs "-dPlatform=${TargetArch}" `
        "-dWixUILicenseRtf=${PackageName}_EULA_${Culture}.rtf"

    $OutputFile = "${PackageName}_${Culture}.msi"

    if ($Culture -eq 'en-US') {
        $OutputFile = "${PackageName}.msi"
    }

    & 'light.exe' "-v" "-nologo" $ObjectFiles "-cultures:${Culture}" "-loc" "${PackageName}_${Culture}.wxl" `
        "-out" $OutputFile $WixArgs "-dPlatform=${TargetArch}" "-sice:ICE61"
}

foreach ($Culture in $($Cultures | Select-Object -Skip 1)) {
    & 'torch.exe' "-v" "${PackageName}.msi" "${PackageName}_${Culture}.msi" "-o" "${Culture}_${TargetArch}.mst"
    & 'cscript.exe' "/nologo" "WiSubStg.vbs" "${PackageName}.msi" "${Culture}_${TargetArch}.mst" "1036"
    & 'cscript.exe' "/nologo" "WiLangId.vbs" "${PackageName}.msi" "Package" "1033,1036"
}
