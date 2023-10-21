Import-Module "$PSScriptRoot/../DevolutionsGateway"

Describe 'Devolutions Gateway certificate import' {
	InModuleScope DevolutionsGateway {
		BeforeAll {
			$DummyPrivateKey = Join-Path $TestDrive 'dummy.key'
			New-Item -Path $DummyPrivateKey -Value 'dummy'
			$ConfigPath = Join-Path $TestDrive 'Gateway'
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
