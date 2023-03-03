Import-Module "$PSScriptRoot/../DevolutionsGateway"

Describe 'Devolutions Gateway certificate import' {
	InModuleScope DevolutionsGateway {
		BeforeAll {
			$DummyPrivateKey = Join-Path $TestDrive 'dummy.key'
			New-Item -Path $DummyPrivateKey -Value 'dummy'

			$ConfigPath = Join-Path $TestDrive 'Gateway'
		}

		It 'Smoke' {
			ForEach ($certFile in Get-ChildItem -Path ./ImportCertificate/WellOrdered) {
				$expected = Get-Content -Path $certFile

				Import-DGatewayCertificate -ConfigPath:$ConfigPath -CertificateFile $certFile -PrivateKeyFile $DummyPrivateKey

				$resultingFile = Join-Path $TestDrive 'Gateway' 'server.crt'
				$result = Get-Content -Path $resultingFile

				$result | Should -Be $expected
			}
		}

		It 'Sorting' {
			ForEach ($unorderedCertFile in Get-ChildItem -Path ./ImportCertificate/Unordered) {
				$wellOrderedCertFile = Join-Path './ImportCertificate/WellOrdered' $unorderedCertFile.Name
				$expected = Get-Content -Path $wellOrderedCertFile

				Import-DGatewayCertificate -ConfigPath:$ConfigPath -CertificateFile $unorderedCertFile -PrivateKeyFile $DummyPrivateKey

				$resultingFile = Join-Path $TestDrive 'Gateway' 'server.crt'
				$result = Get-Content -Path $ResultingFile

				$result | Should -Be $expected
			}
		}
	}
}
