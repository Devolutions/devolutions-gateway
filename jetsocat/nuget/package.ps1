$ErrorActionPreference = "Stop"

function Package-Jetsocat {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AccessToken,

        [Parameter(Mandatory=$True)]
        [string]$Version
    )

    New-Item -ItemType Directory -Force -Path "bin"

    $Org = "Devolutions"
    $Repo = "devolutions-gateway" # public repo, no API key needed
    $Architectures = ( "x86_64" )

    $Release = Invoke-WebRequest https://api.github.com/repos/$Org/$Repo/releases/latest -Headers @{ 
        "accept" = "application/json" 
        "authorization" = "Bearer $AccessToken"
    }
    $ReleaseJson = $Release.Content | ConvertFrom-Json
    $JetsocatVersion = $ReleaseJson.tag_name

    foreach ($Architecture in $Architectures) {
        $ArchDir = $Architecture

        if ($Architecture -eq "x86_64") {
            $ArchDir = "x64"
        }

        $DestPath = Join-Path -Path "bin" -ChildPath $ArchDir
        New-Item -ItemType Directory -Force -Path $DestPath
        $Asset = $ReleaseJson.assets | Where-Object name -Match "jetsocat_windows_.*_${Architecture}.exe"

        Invoke-WebRequest $Asset.url -Headers @{ 
            "accept" = "application/octet-stream" 
            "authorization" = "Bearer $AccessToken"
        } -OutFile (Join-Path -Path $DestPath -ChildPath "jetsocat.exe")
    }

    $Nuspec = (Resolve-Path "Devolutions.Jetsocat.nuspec")
    $Xml = [xml] (Get-Content $Nuspec)
    Select-Xml -xml $Xml -XPath //package/metadata/version | % { $_.Node.'#text' = "$Version" }
    Select-Xml -xml $Xml -XPath //package/metadata/description | % { $_.Node.'#text' = "Websocket toolkit for jet protocol related operations (jetsocat $JetsocatVersion)" }
    $Xml.Save($Nuspec)

    nuget pack Devolutions.Jetsocat.nuspec -NonInteractive
}

Package-Jetsocat @args
