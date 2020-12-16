
. "$PSScriptRoot/../Private/CertificateHelper.ps1"

function ConvertTo-Base64Url
{
    [CmdletBinding()]
    [OutputType('System.String')]
    param(
        [Parameter(ParameterSetName='String',Mandatory=$true,Position=0)]
        [AllowEmptyString()]
        [string] $Text,
        [Parameter(ParameterSetName='Bytes',Mandatory=$true,Position=0)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    if ($PSCmdlet.ParameterSetName -eq 'String') {
        $Bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    }

    [Convert]::ToBase64String($Bytes).Split('=')[0].Replace('+','-').Replace('/','_')
}

function New-JwtRs256
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject] $Header,
        [Parameter(Mandatory=$true)]
        [PSCustomObject] $Payload,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.RSA] $PrivateKey
    )

    if (-Not $Header.PSObject.Properties['typ']) {
        $Header | Add-Member -MemberType NoteProperty -Name 'typ' -Value 'JWT'
    }

    if (-Not $Header.PSObject.Properties['alg']) {
        $Header | Add-Member -MemberType NoteProperty -Name 'alg' -Value 'RS256'
    }

    $HeaderJson = $Header | ConvertTo-Json -Compress | Out-String
    $PayloadJson = $Payload | ConvertTo-Json -Compress | Out-String
    
    $HeaderText = ConvertTo-Base64Url $HeaderJson
    $PayloadText = ConvertTo-Base64Url $PayloadJson
    
    $SignText = $HeaderText + '.' + $PayloadText
    $SignBytes = [System.Text.Encoding]::UTF8.GetBytes($SignText)
    
    $Signature = ConvertTo-Base64Url $PrivateKey.SignData($SignBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    
    $SignText + '.' + $Signature # Final JWT
}
