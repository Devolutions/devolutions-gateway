param([hashtable] $Lab)

BeforeAll {
    Import-Module "$PSScriptRoot\..\src\GatewayLab.psm1" -Force
    $script:target = $Lab.Accounts | Where-Object Kind -eq 'Local' | Select-Object -First 1
    if (-not $script:target) { throw 'Certificate migration requires the Local account fixture' }
}

Describe 'System certificate account migration using <Provider>' -ForEach @(
    @{ Provider = 'Microsoft Software Key Storage Provider'; Label = 'cng' }
    @{ Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'; Label = 'csp' }
) {
    BeforeAll {
        $script:caseDirectory = (New-Item -ItemType Directory -Path "$($Lab.Output)\certificate-$Label").FullName
        $script:installed = $null
        $script:certificate = $null
    }

    It 'preserves configuration and grants the replacement account TLS key access' {
        Invoke-GatewayLabMsi -Msi $Lab.Msi -LogPath "$script:caseDirectory\install.log" | Should -Be 0
        $script:installed = $Lab.Msi
        Initialize-GatewayLabConfiguration -Port $Lab.Port
        $script:certificate = New-SelfSignedCertificate -DnsName 'localhost' -Subject "CN=GatewayLab-$($Lab.RunId)-$Label" `
            -CertStoreLocation 'Cert:\LocalMachine\My' -Provider $Provider -KeyAlgorithm RSA -KeyLength 2048 `
            -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(2)
        $path = Join-Path $env:ProgramData 'Devolutions\Gateway\gateway.json'
        $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $settings = @{
            TlsCertificateSource = 'System'; TlsCertificateSubjectName = "GatewayLab-$($Lab.RunId)-$Label"
            TlsCertificateStoreName = 'My'; TlsCertificateStoreLocation = 'LocalMachine'; TlsVerifyStrict = $false
            Listeners = @(@{ InternalUrl = "https://127.0.0.1:$($Lab.Port)"; ExternalUrl = "https://127.0.0.1:$($Lab.Port)" })
        }
        foreach ($key in $settings.Keys) { $config | Add-Member -NotePropertyName $key -NotePropertyValue $settings[$key] -Force }
        [IO.File]::WriteAllText($path, ($config | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $hash = (Get-FileHash -LiteralPath $path).Hash
        Invoke-GatewayLabMsi -Msi $Lab.NextMsi -LogPath "$script:caseDirectory\switch-account.log" -Properties @{
            'P.SERVICEACCOUNT' = $script:target.Name
            'P.SERVICEPASSWORD' = $script:target.Credential.GetNetworkCredential().Password
        } | Should -Be 0
        $script:installed = $Lab.NextMsi
        (Get-FileHash -LiteralPath $path).Hash | Should -Be $hash
        Start-Service DevolutionsGateway
        $service = Wait-GatewayLabService Running
        $probe = Invoke-GatewayLabServiceProbe -ProcessId ([int]$service.ProcessId) -OutputDirectory $script:caseDirectory
        $probe.UserSid | Should -Be $script:target.Sid
        [GatewayInstallerTests.ServiceProbe]::CheckTls($Lab.Port, $script:certificate.Thumbprint)
    }

    AfterAll {
        if (Test-GatewayLabRecoveryRequired) { throw 'Retaining certificate fixtures for recovery after a reboot-required result or timeout' }
        if ($script:installed) {
            Stop-GatewayLabService
            Invoke-GatewayLabMsi -Msi $script:installed -Action Uninstall -LogPath "$script:caseDirectory\uninstall.log" | Out-Null
        }
        if ((Get-GatewayLabState).Service) { throw 'Service remains installed; retaining certificate and data' }
        if ($script:certificate) { Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($script:certificate.Thumbprint)" -DeleteKey }
        $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
        if (Test-Path -LiteralPath $data) {
            Move-Item -LiteralPath $data -Destination "$script:caseDirectory\retained-data"
            Protect-GatewayLabArtifacts -Directory "$script:caseDirectory\retained-data"
        }
    }
}
