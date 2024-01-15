Import-Module "$PSScriptRoot/../DevolutionsGateway"

Describe 'Devolutions Gateway config' {
	InModuleScope DevolutionsGateway {
		BeforeAll {
			$ConfigPath = Join-Path $TestDrive 'Gateway'
		}

		Context 'Fresh environment' {
			It 'Creates basic configuration' {
				Remove-Item (Join-Path $ConfigPath 'gateway.json') -ErrorAction SilentlyContinue | Out-Null
				Set-DGatewayConfig -ConfigPath:$ConfigPath -Hostname 'gateway.local'
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).Hostname | Should -Be 'gateway.local'
			}

			It 'Sets gateway hostname' {
				Set-DGatewayHostname -ConfigPath:$ConfigPath 'host1.gateway.local'
				$(Get-DGatewayHostname -ConfigPath:$ConfigPath) | Should -Be 'host1.gateway.local'
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
				Set-DGatewayConfig -ConfigPath:$ConfigPath -RecordingPath $RecordingPath
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).RecordingPath | Should -Be $RecordingPath
			}

			It 'Sets log verbosity profile' {
				Set-DGatewayConfig -ConfigPath:$ConfigPath -VerbosityProfile 'All'
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).VerbosityProfile | Should -Be 'All'
				Set-DGatewayConfig -ConfigPath:$ConfigPath -VerbosityProfile 'Default'
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).VerbosityProfile | Should -Be 'Default'
				Set-DGatewayConfig -ConfigPath:$ConfigPath -VerbosityProfile 'Tls'
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).VerbosityProfile | Should -Be 'Tls'
				{ Set-DGatewayConfig -ConfigPath:$ConfigPath -VerbosityProfile 'yolo' } | Should -Throw
			}

			It 'Sets ngrok configuration' {
				$AuthToken = '4nq9771bPxe8ctg7LKr_2ClH7Y15Zqe4bWLWF9p'
				$Metadata = '{"serial": "00012xa-33rUtz9", "comment": "For customer alan@example.com"}'
				$HeartbeatInterval = 15
				$HeartbeatTolerance = 5
				$ngrok = New-DGatewayNgrokConfig -AuthToken $AuthToken
				$ngrok.Metadata = $Metadata
				$ngrok.HeartbeatInterval = $HeartbeatInterval
				$ngrok.HeartbeatTolerance = $HeartbeatTolerance
				$httpTunnelParams = @{
					Http = $true
					Metadata = "c6481452-6f5d-11ee-b962-0242ac120002"
					AllowCidrs = @("0.0.0.0/0")
					Domain = "gateway.ngrok.io"
					CircuitBreaker = 0.5
					Compression = $true
				}
				$tcpTunnelParams = @{
					Tcp = $true
					AllowCidrs = @("0.0.0.0/0")
					RemoteAddr = "7.tcp.ngrok.io:20560"
				}
				$httpTunnel = New-DGatewayNgrokTunnel @httpTunnelParams
				$tcpTunnel = New-DGatewayNgrokTunnel @tcpTunnelParams
				$ngrok.Tunnels = [PSCustomObject]@{
					"http-endpoint" = $httpTunnel
					"tcp-endpoint" = $tcpTunnel
				}
				Set-DGatewayConfig -ConfigPath:$ConfigPath -Ngrok $ngrok
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).Ngrok.AuthToken | Should -Be $AuthToken
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).Ngrok.Metadata | Should -Be $Metadata
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).Ngrok.HeartbeatInterval | Should -Be $HeartbeatInterval
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).Ngrok.HeartbeatTolerance | Should -Be $HeartbeatTolerance
				$Tunnels = $(Get-DGatewayConfig -ConfigPath:$ConfigPath).Ngrok.Tunnels
				$Tunnels.'http-endpoint'.Proto | Should -Be 'http'
				$Tunnels.'http-endpoint'.Domain | Should -Be $httpTunnel.Domain
				$Tunnels.'http-endpoint'.Metadata | Should -Be $httpTunnel.Metadata
				$Tunnels.'http-endpoint'.AllowCidrs | Should -Be $httpTunnel.AllowCidrs
				$Tunnels.'tcp-endpoint'.Proto | Should -Be 'tcp'
				$Tunnels.'tcp-endpoint'.RemoteAddr | Should -Be $tcpTunnel.RemoteAddr
				$Tunnels.'tcp-endpoint'.AllowCidrs | Should -Be $tcpTunnel.AllowCidrs
			}

			It 'Sets TLS certificate configuration' {
				$Params = @{
					TlsCertificateSource = "System"
					TlsCertificateSubjectName = "dvls.ad.it-help.ninja"
					TlsCertificateStoreName = "My"
					TlsCertificateStoreLocation = "LocalMachine"
				}
				Set-DGatewayConfig -ConfigPath:$ConfigPath @Params
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).TlsCertificateSource | Should -Be "System"
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).TlsCertificateSubjectName | Should -Be "dvls.ad.it-help.ninja"
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).TlsCertificateStoreName | Should -Be "My"
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).TlsCertificateStoreLocation | Should -Be "LocalMachine"
			}

			It 'Sets web app configuration' {
				$Params = @{
					Enabled = $true
					Authentication = "None"
				}
				$WebApp = New-DGatewayWebAppConfig @Params
				Set-DGatewayConfig -ConfigPath:$ConfigPath -WebApp $WebApp
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).WebApp.Enabled | Should -Be $true
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).WebApp.Authentication | Should -Be "None"

				$WebApp.Enabled = $false
				Set-DGatewayConfig -ConfigPath:$ConfigPath -WebApp $WebApp
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).WebApp.Enabled | Should -Be $false

				$WebApp.Enabled = $true
				$WebApp.Authentication = "Custom"
				$WebApp.AppTokenMaximumLifetime = 600 # 10 minutes
				$WebApp.LoginLimitRate = 8
				Set-DGatewayConfig -ConfigPath:$ConfigPath -WebApp $WebApp
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).WebApp.Enabled | Should -Be $true
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).WebApp.Authentication | Should -Be "Custom"
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).WebApp.AppTokenMaximumLifetime | Should -Be 600
				$(Get-DGatewayConfig -ConfigPath:$ConfigPath).WebApp.LoginLimitRate | Should -Be 8
			}
		}
	}
}
