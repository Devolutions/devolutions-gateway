Import-Module "$PSScriptRoot/../DevolutionsGateway"

Describe 'Devolutions Gateway config' {
	InModuleScope DevolutionsGateway {
		Context 'Fresh environment' {
			It 'Creates basic configuration' {
				$ConfigPath = Join-Path $TestDrive 'Gateway'
				Set-DGatewayConfig -ConfigPath:$ConfigPath -Hostname 'gateway.local' -DockerRestartPolicy 'no'
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).Hostname | Should -Be 'gateway.local'
			}

			It 'Sets gateway hostname' {
				$ConfigPath = Join-Path $TestDrive 'Gateway'
				Set-DGatewayHostname -ConfigPath:$ConfigPath 'host1.gateway.local'
				$(Get-DGatewayHostname -ConfigPath:$ConfigPath) | Should -Be 'host1.gateway.local'
			}

			It 'Sets gateway farm name' {
				$ConfigPath = Join-Path $TestDrive 'Gateway'
				Set-DGatewayFarmName -ConfigPath:$ConfigPath 'farm.gateway.local'
				$(Get-DGatewayFarmName -ConfigPath:$ConfigPath) | Should -Be 'farm.gateway.local'
			}

			It 'Sets gateway farm members' {
				$ConfigPath = Join-Path $TestDrive 'Gateway'
				$FarmMembers = @('host1.gateway.local','host2.gateway.local','host3.gateway.local')
				Set-DGatewayFarmMembers -ConfigPath:$ConfigPath $FarmMembers
				$(Get-DGatewayFarmMembers -ConfigPath:$ConfigPath) | Should -Be $FarmMembers
			}

			It 'Sets gateway listeners' {
				$ConfigPath = Join-Path $TestDrive 'Gateway'
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
		}
	}
}
