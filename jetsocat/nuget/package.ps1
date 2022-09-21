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
    $Repo = "devolutions-gateway"
    $Platforms = ( "windows", "macos" )

    $Release = Invoke-WebRequest https://api.github.com/repos/$Org/$Repo/releases/latest -Headers @{ 
        "accept" = "application/json" 
        "authorization" = "Bearer $AccessToken"
    }
    $ReleaseJson = $Release.Content | ConvertFrom-Json
    $JetsocatVersion = $ReleaseJson.tag_name

    foreach ($Platform in $Platforms) {
        $Architectures = switch ($Platform) {
            'windows' { ('x86_64') }
            'macos' { ('x86_64', 'arm64', 'universal') }
        }

        foreach ($Architecture in $Architectures) {
            Write-Host $Platform $Architecture

            $ArchDir = $Architecture

            if ($Architecture -eq "x86_64") {
                $ArchDir = "x64"
            }

            $DestPath = Join-Path "bin" $Platform $ArchDir
            New-Item -ItemType Directory -Force -Path $DestPath
            $Asset = $ReleaseJson.assets | Where-Object name -Match "jetsocat_${Platform}_.*_${Architecture}*"

            $OutFile = "jetsocat"

            if ($Platform -Eq "windows") {
                $OutFile += ".exe"
            }

            Invoke-WebRequest $Asset.url -Headers @{ 
                "accept" = "application/octet-stream" 
                "authorization" = "Bearer $AccessToken"
            } -OutFile (Join-Path -Path $DestPath -ChildPath $OutFile)
        }
    }

    $Nuspec = (Resolve-Path "Devolutions.Jetsocat.nuspec")
    $Xml = [xml] (Get-Content $Nuspec)
    Select-Xml -xml $Xml -XPath //package/metadata/version | % { $_.Node.'#text' = "$Version" }
    Select-Xml -xml $Xml -XPath //package/metadata/description | % { $_.Node.'#text' = "Websocket toolkit for jet protocol related operations (jetsocat $JetsocatVersion)" }
    $Xml.Save($Nuspec)

    nuget pack Devolutions.Jetsocat.nuspec -NonInteractive
}

Package-Jetsocat @args
