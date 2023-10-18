Import-Module "$PSScriptRoot/../DevolutionsGateway"

Describe 'Devolutions Gateway config' {
	InModuleScope DevolutionsGateway {
		BeforeAll {
			$ConfigPath = Join-Path $TestDrive 'Gateway'
		}

		Context 'Fresh environment' {
			It 'Creates basic configuration' {
				Set-DGatewayConfig -ConfigPath:$ConfigPath -Hostname 'gateway.local' -DockerRestartPolicy 'no'
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).Hostname | Should -Be 'gateway.local'
			}

			It 'Sets gateway hostname' {
				Set-DGatewayHostname -ConfigPath:$ConfigPath 'host1.gateway.local'
				$(Get-DGatewayHostname -ConfigPath:$ConfigPath) | Should -Be 'host1.gateway.local'
			}

			It 'Sets gateway farm name' {
				Set-DGatewayFarmName -ConfigPath:$ConfigPath 'farm.gateway.local'
				$(Get-DGatewayFarmName -ConfigPath:$ConfigPath) | Should -Be 'farm.gateway.local'
			}

			It 'Sets gateway farm members' {
				$FarmMembers = @('host1.gateway.local','host2.gateway.local','host3.gateway.local')
				Set-DGatewayFarmMembers -ConfigPath:$ConfigPath $FarmMembers
				$(Get-DGatewayFarmMembers -ConfigPath:$ConfigPath) | Should -Be $FarmMembers
			}

			It 'Sets gateway listeners' {
				$HttpListener = New-DGatewayListener 'http://*:4040' 'http://*:4040'
				$WsListener = New-DGatewayListener 'ws://*:4040' 'ws://*:4040'
				$TcpListener = New-DGatewayListener 'tcp://*:4041' 'tcp://*:4041'

				$ExpectedListeners = @($HttpListener, $WsListener, $TcpListener)
				Set-DGatewayConfig -ConfigPath:$ConfigPath -Listeners $ExpectedListeners
				$ActualListeners = Get-DGatewayListeners -ConfigPath:$ConfigPath
				$ExpectedListeners.Count | Should -Be $ActualListeners.Count

				$ExpectedListeners = @($HttpListener, $TcpListener)
				Set-DGatewayListeners -ConfigPath:$ConfigPath $ExpectedListeners
				$ActualListeners = Get-DGatewayListeners -ConfigPath:$ConfigPath
				$ExpectedListeners.Count | Should -Be $ActualListeners.Count
			}

			It 'Sets gateway recording path' {
				$RecordingPath = "C:\Users\Public\Gateway\Recordings"
				$DefaultRecordingPath = Join-Path $ConfigPath "recordings"
				Set-DGatewayRecordingPath -ConfigPath:$ConfigPath $RecordingPath
				$(Get-DGatewayRecordingPath -ConfigPath:$ConfigPath) | Should -Be $RecordingPath
				Reset-DGatewayRecordingPath -ConfigPath:$ConfigPath
				$(Get-DGatewayRecordingPath -ConfigPath:$ConfigPath) | Should -Be $DefaultRecordingPath
			}
		}
	}
}
