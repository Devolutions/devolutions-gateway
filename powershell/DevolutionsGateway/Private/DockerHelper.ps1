
class DockerHealthcheck
{
    [string] $Test
    [string] $Interval
    [string] $Timeout
    [string] $Retries
    [string] $StartPeriod

    DockerHealthcheck() { }

    DockerHealthcheck([string] $Test) {
        $this.Test = $Test
        $this.Interval = "5s"
        $this.Timeout = "2s"
        $this.Retries = "5"
        $this.StartPeriod = "1s"
    }

    DockerHealthcheck([DockerHealthcheck] $other) {
        $this.Test = $other.Test
        $this.Interval = $other.Interval
        $this.Timeout = $other.Timeout
        $this.Retries = $other.Retries
        $this.StartPeriod = $other.StartPeriod
    }
}

class DockerLogging
{
    [string] $Driver
    [Hashtable] $Options

    DockerLogging() { }

    DockerLogging([string] $SyslogAddress) {
        $this.Driver = "syslog"
        $this.Options = [ordered]@{
            'syslog-format' = 'rfc5424'
            'syslog-facility' = 'daemon'
            'syslog-address' = $SyslogAddress
        }
    }

    DockerLogging([DockerLogging] $other) {
        $this.Driver = $other.Driver

        if ($other.Options) {
            $this.Options = $other.Options.Clone()
        }
    }
}

class DockerService
{
    [string] $Image
    [string] $Platform
    [string] $Isolation
    [string] $ContainerName
    [string] $RestartPolicy
    [bool] $External
    [string[]] $DependsOn
    [string[]] $Networks
    [Hashtable] $Environment
    [string[]] $Volumes
    [string] $Command
    [Int32[]] $TargetPorts
    [bool] $PublishAll
    [DockerHealthcheck] $Healthcheck
    [DockerLogging] $Logging

    DockerService() { }

    DockerService([DockerService] $other) {
        $this.Image = $other.Image
        $this.Platform = $other.Platform
        $this.Isolation = $other.Isolation
        $this.ContainerName = $other.ContainerName
        $this.RestartPolicy = $other.RestartPolicy

        $this.External = $other.External

        if ($other.DependsOn) {
            $this.DependsOn = $other.DependsOn.Clone()
        }

        if ($other.Networks) {
            $this.Networks = $other.Networks.Clone()
        }

        if ($other.Environment) {
            $this.Environment = $other.Environment.Clone()
        }

        if ($other.Volumes) {
            $this.Volumes = $other.Volumes.Clone()
        }
    
        $this.Command = $other.Command

        if ($other.TargetPorts) {
            $this.TargetPorts = $other.TargetPorts.Clone()
        }

        $this.PublishAll = $other.PublishAll

        if ($other.Healthcheck) {
            $this.Healthcheck = [DockerHealthcheck]::new($other.Healthcheck)
        }
     
        if ($other.Logging)  {
            $this.Logging = [DockerLogging]::new($other.Logging)
        }
    }
}

function Start-DockerService
{
    [CmdletBinding()]
    param(
        [DockerService] $Service,
        [switch] $Remove
    )

    if ($Service.External) {
        return # service should already be running
    }

    if (Get-ContainerExists -Name $Service.ContainerName) {
        if (Get-ContainerIsRunning -Name $Service.ContainerName) {
            Stop-Container -Name $Service.ContainerName
        }

        if ($Remove) {
            Remove-Container -Name $Service.ContainerName
        }
    }

    $RunCommand = (Get-DockerRunCommand -Service $Service) -Join " "

    Write-Host "Starting $($Service.ContainerName)"
    Write-Verbose $RunCommand

    $id = Invoke-Expression $RunCommand

    if ($Service.Healthcheck) {
        Wait-ContainerHealthy -Name $Service.ContainerName | Out-Null
    }

    if (Get-ContainerIsRunning -Name $Service.ContainerName) {
        Write-Host "$($Service.ContainerName) successfully started"
    } else {
        throw "Error starting $($Service.ContainerName)"
    }
}

function Get-ContainerExists
{
    param(
        [string] $Name
    )

    $exists = $(docker ps -aqf "name=$Name")
    return ![string]::IsNullOrEmpty($exists)
}

function Get-ContainerIsRunning
{
    param(
        [string] $Name
    )

    $running = $(docker inspect -f '{{.State.Running}}' $Name)
    return $running -Match 'true'
}

function Get-ContainerIsHealthy
{
    param(
        [string] $Name
    )

    $healthy = $(docker inspect -f '{{.State.Health.Status}}' $Name)
    return $healthy -Match 'healthy'
}

function Wait-ContainerHealthy
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name
    )

    $seconds = 0
    $timeout = 15
    $interval = 1

    while (($seconds -lt $timeout) -And !(Get-ContainerIsHealthy -Name:$Name) -And (Get-ContainerIsRunning -Name:$Name)) {
        Start-Sleep -Seconds $interval
        $seconds += $interval
    }

    return (Get-ContainerIsHealthy -Name:$Name)
}

function Stop-Container
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [switch] $Quiet
    )

    $CmdArgs = @('docker', 'stop')

    $CmdArgs += $Name
    $cmd = $CmdArgs -Join " "

    if (-Not $Quiet) {
        Write-Host $cmd
    }

    Invoke-Expression $cmd | Out-Null
}

function Remove-Container
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [switch] $Quiet,
        [switch] $Force
    )

    $CmdArgs = @('docker', 'rm')

    if ($Force) {
        $CmdArgs += '-f'
    }

    $CmdArgs += $Name
    $cmd = $CmdArgs -Join " "

    if (-Not $Quiet) {
        Write-Host $cmd
    }

    Invoke-Expression $cmd | Out-Null
}

function Get-DockerNetworkExists
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name
    )

    $exists = $(docker network ls -qf "name=$Name")
    return ![string]::IsNullOrEmpty($exists)
}

function New-DockerNetwork
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [string] $Platform,
        [switch] $Force
    )

    if (!(Get-DockerNetworkExists -Name:$Name)) {
        $cmd = @('network', 'create')
        
        if ($Platform -eq 'windows') {
            $cmd += @('-d', 'nat')
        }

        $cmd += $Name # network name
        $Id = docker $cmd
    }
}

function New-DockerVolume
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [switch] $Force
    )

    $output = $(docker volume ls -qf "name=$Name")

    if ([string]::IsNullOrEmpty($output)) {
        docker volume create $Name | Out-Null
    }
}

function Request-ContainerImage()
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [switch] $Quiet
    )

    $CmdArgs = @('docker', 'pull')

    if ($Quiet) {
        $CmdArgs += '-q'
    }

    $CmdArgs += $Name
    $cmd = $CmdArgs -Join " "

    if (-Not $Quiet) {
        Write-Host $cmd
    }

    Invoke-Expression $cmd | Out-Null
}

function Get-ContainerImageId()
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name
    )

    if ($Name.StartsWith("library/")) {
        $Name = $Name -Replace "library/", ""
    }

    $CmdArgs = @('docker', 'images', '-q')
    $CmdArgs += $Name
    $cmd = $CmdArgs -Join " "

    $Id = Invoke-Expression $cmd
    return $Id
}

function Test-DockerHost
{
    [CmdletBinding()]
    param()

    if (Get-IsWindows) {
        $DnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | `
            Select-Object -Unique -ExpandProperty ServerAddresses

        if ($DnsServers -Contains '127.0.0.1') {
            Write-Warning "A DNS server with address 127.0.0.1 is configured on the host."
            Write-Warning "This is known to cause DNS resolution issues inside containers."
            Write-Warning "Please use the host IP address from the host network instead."
        }

        $SEP = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | `
            ForEach-Object { Get-ItemProperty $_.PSPath } | `
            Where-Object { $_ -Match 'Symantec Endpoint Protection' }

        if ($SEP) {
            Write-Warning "Symantec Endpoint Protection (SEP) has been detected."
            Write-Warning "It is known to cause several issues with Docker for Windows."
            Write-Warning "Removing the 'Application and Device Control' (ADC) component is recommended."
            Write-Warning "Please refer to the following article for the relevant exclusions:"
            Write-Warning "https://knowledge.broadcom.com/external/article?legacyId=TECH246815"
            Write-Warning "You should also add %ProgramData%\docker to the exclusion list:"
            Write-Warning "https://docs.docker.com/engine/security/antivirus/"
            Write-Warning "At last, you can refer to the following blog article for further guidance:"
            Write-Warning "https://mdaslam.wordpress.com/2017/05/23/docker-container-windows-2016-server-with-sep-symantec-endpoint-protection/"
        }
    }
}

function Get-DockerRunCommand
{
    [OutputType('string[]')]
    param(
        [DockerService] $Service
    )

    $cmd = @('docker', 'run')

    $cmd += @('--name', $Service.ContainerName)

    $cmd += "-d" # detached

    if ($Service.Platform -eq 'windows') {
        if ($Service.Isolation -eq 'hyperv') {
            $cmd += "--isolation=$($Service.Isolation)"
        }
    }

    if ($Service.RestartPolicy) {
        $cmd += "--restart=$($Service.RestartPolicy)"
    }

    if ($Service.Networks) {
        foreach ($Network in $Service.Networks) {
            $cmd += "--network=$Network"
        }
    }

    if ($Service.Environment) {
        $Service.Environment.GetEnumerator() | foreach {
            $key = $_.Key
            $val = $_.Value
            $cmd += @("-e", "`"$key=$val`"")
        }
    }

    if ($Service.Volumes) {
        foreach ($Volume in $Service.Volumes) {
            $cmd += @("-v", "`"$Volume`"")
        }
    }

    if ($Service.PublishAll) {
        foreach ($TargetPort in $Service.TargetPorts) {
            $cmd += @("-p", "$TargetPort`:$TargetPort")
        }
    }

    if ($Service.Healthcheck) {
        $Healthcheck = $Service.Healthcheck
        if (![string]::IsNullOrEmpty($Healthcheck.Interval)) {
            $cmd += "--health-interval=" + $Healthcheck.Interval
        }
        if (![string]::IsNullOrEmpty($Healthcheck.Timeout)) {
            $cmd += "--health-timeout=" + $Healthcheck.Timeout
        }
        if (![string]::IsNullOrEmpty($Healthcheck.Retries)) {
            $cmd += "--health-retries=" + $Healthcheck.Retries
        }
        if (![string]::IsNullOrEmpty($Healthcheck.StartPeriod)) {
            $cmd += "--health-start-period=" + $Healthcheck.StartPeriod
        }
        $cmd += $("--health-cmd=`'" + $Healthcheck.Test + "`'")
    }

    if ($Service.Logging) {
        $Logging = $Service.Logging
        $cmd += '--log-driver=' + $Logging.Driver

        $options = @()
        $Logging.Options.GetEnumerator() | foreach {
            $key = $_.Key
            $val = $_.Value
            $options += "$key=$val"
        }

        $options = $options -Join ","
        $cmd += "--log-opt=" + $options
    }

    $cmd += $Service.Image
    $cmd += $Service.Command

    return $cmd
}
