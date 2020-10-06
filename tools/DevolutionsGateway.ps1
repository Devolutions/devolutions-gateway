
function Register-GatewayService
{
    $ServiceName = "devolutions-gateway"
    $DisplayName = "Devolutions Gateway"
    $Description = "Devolutions Gateway service"

    $CompanyDir = "Devolutions"
    $ProgramDir = "Gateway"
    $Executable = "DevolutionsGateway.exe"

    $params = @{
        Name = $ServiceName
        DisplayName = $DisplayName
        Description = $Description
        WorkingDir = "%ProgramData%\${CompanyDir}\${ProgramDir}"
        BinaryPathName = "%ProgramFiles%\${CompanyDir}\${ProgramDir}\${Executable}"
    }

    New-Service @params
}

function New-JetToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $DestinationHost
    )

    $CompanyDir = "Devolutions"
    $ProgramDir = "Gateway"

    $PublicKeyFile = [System.Environment]::ExpandEnvironmentVariables("%ProgramData%\${CompanyDir}\${ProgramDir}\public.pem")
    $PrivateKeyFile = [System.Environment]::ExpandEnvironmentVariables("%ProgramData%\${CompanyDir}\${ProgramDir}\private.key")

    $raw_token = [PSCustomObject]@{
        jet_ap = 'rdp'
        jet_cm = 'fwd'
        dst_host = $DestinationHost
    } | ConvertTo-Json | Out-String

    Write-Host $raw_token

    $nbf_date = Get-Date
    $exp_date = $nbf_date.AddMinutes(2).AddDays(7)

    $nbf = [System.DateTimeOffset]::new($nbf_date).ToUnixTimeSeconds()
    $exp = [System.DateTimeOffset]::new($exp_date).ToUnixTimeSeconds()

    $jwt = $raw_token | & 'step' 'crypto' 'jwt' 'sign' '-' '-nbf' $nbf '-exp' $exp '-subtle' '-key' $PrivateKeyFile

    Write-Host "|$jwt|"
    $jwe = "$jwt" | & 'step' 'crypto' 'jwe' 'encrypt' '-alg' 'RSA-OAEP-256' '-enc' 'A256GCM' '-key' $PublicKeyFile
    Write-Host "|$jwe|"
    $jwe = "$jwe" | & 'step' 'crypto' 'jose' 'format'
    Write-Host "|$jwe|"
}

New-JetToken -DestinationHost 'DFORD-PC'
