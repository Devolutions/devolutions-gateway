Import-Module "$PSScriptRoot/../DevolutionsGateway"

Describe 'Devolutions Gateway certificate import' {
	InModuleScope DevolutionsGateway {
		BeforeAll {
			$DummyPrivateKey = Join-Path $TestDrive 'dummy.key'
			New-Item -Path $DummyPrivateKey -Value 'dummy'
			$ConfigPath = Join-Path $TestDrive 'Gateway'
		}

		It 'Import self-signed .pfx certificate with key' {
			$CertificateFile = Get-Item -Path ".\ImportCertificate\SelfSigned\localhost.pfx"
			$ExpectedCertificateData = Get-Content -Path ".\ImportCertificate\SelfSigned\localhost.crt"
			$ExpectedPrivateKeyData = Get-Content -Path ".\ImportCertificate\SelfSigned\localhost.key"
			$PasswordFile = [System.IO.Path]::ChangeExtension($CertificateFile.FullName, ".pwd")
			$Password = (Get-Content -Path $PasswordFile -Raw).Trim()
			Import-DGatewayCertificate -ConfigPath:$ConfigPath -CertificateFile $CertificateFile -Password $Password

			$ActualCertificateData = Get-Content -Path (Join-Path $ConfigPath 'server.crt')
			$ActualPrivateKeyData = Get-Content -Path (Join-Path $ConfigPath 'server.key')
			$ActualCertificateData | Should -Be $ExpectedCertificateData
			$ActualPrivateKeyData | Should -Be $ExpectedPrivateKeyData
		}

		It 'Smoke' {
			(Get-Item -Path ".\ImportCertificate\WellOrdered\*.crt") | ForEach-Object {
				$CertFile = $_.FullName
				$expected = Get-Content -Path $certFile

				Import-DGatewayCertificate -ConfigPath:$ConfigPath -CertificateFile $certFile -PrivateKeyFile $DummyPrivateKey

				$resultingFile = Join-Path $ConfigPath 'server.crt'
				$result = Get-Content -Path $resultingFile

				$result | Should -Be $expected
			}
		}

		It 'Sorting' {
			(Get-Item -Path ".\ImportCertificate\Unordered\*.crt") | ForEach-Object {
				$unorderedCertFile = $_.FullName
				$wellOrderedCertFile = $_.FullName -Replace 'Unordered', 'WellOrdered'
				$expected = Get-Content -Path $wellOrderedCertFile

				Import-DGatewayCertificate -ConfigPath:$ConfigPath -CertificateFile $unorderedCertFile -PrivateKeyFile $DummyPrivateKey

				$resultingFile = Join-Path $ConfigPath 'server.crt'
				$result = Get-Content -Path $ResultingFile

				$result | Should -Be $expected
			}
		}
	}
}
