
function ConvertFrom-RsaPublicKey
{
    [OutputType('System.String')]
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.RSA] $Rsa
    )

    $stream = [System.IO.MemoryStream]::new()
    $writer = [PemUtils.PemWriter]::new($stream)
    $writer.WritePublicKey($Rsa)
    $stream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
    [System.IO.StreamReader]::new($stream).ReadToEnd()
}

function ConvertTo-RsaPublicKey
{
    [OutputType('System.Security.Cryptography.RSA')]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Pem
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Pem)
    $stream = [System.IO.MemoryStream]::new($bytes)
    $reader = [PemUtils.PemReader]::new($stream)
    $params = $reader.ReadRsaKey();
    [System.Security.Cryptography.RSA]::Create($params)
}

function ConvertFrom-RsaPrivateKey
{
    [OutputType('System.String')]
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.RSA] $Rsa
    )

    $stream = [System.IO.MemoryStream]::new()
    $writer = [PemUtils.PemWriter]::new($stream)
    $writer.WritePrivateKey($Rsa)
    $stream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
    [System.IO.StreamReader]::new($stream).ReadToEnd().Trim()
}

function ConvertTo-RsaPrivateKey
{
    [OutputType('System.Security.Cryptography.RSA')]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Pem
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Pem)
    $stream = [System.IO.MemoryStream]::new($bytes)
    $reader = [PemUtils.PemReader]::new($stream)
    $params = $reader.ReadRsaKey();
    [System.Security.Cryptography.RSA]::Create($params)
}

function New-RsaKeyPair
{
    param(
        [int] $KeySize = 2048
    )

    $Rsa = [System.Security.Cryptography.RSA]::Create($KeySize)
    $PublicKey = ConvertFrom-RsaPublicKey -Rsa $Rsa
    $PrivateKey = ConvertFrom-RsaPrivateKey -Rsa $Rsa

    return [PSCustomObject]@{
        PublicKey = $PublicKey
        PrivateKey = $PrivateKey
    }
}

function ConvertTo-PemEncoding
{
    [OutputType('System.String')]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Label,
        [Parameter(Mandatory=$true)]
        [byte[]] $RawData
    )

    $base64 = [Convert]::ToBase64String($RawData)

	$offset = 0
	$line_length = 64
	$sb = [System.Text.StringBuilder]::new()
	$sb.AppendLine("-----BEGIN $label-----") | Out-Null
	while ($offset -lt $base64.Length) {
		$line_end = [Math]::Min($offset + $line_length, $base64.Length)
		$sb.AppendLine($base64.Substring($offset, $line_end - $offset)) | Out-Null
		$offset = $line_end
	}
	$sb.AppendLine("-----END $label-----") | Out-Null

	return $sb.ToString().Trim()
}

function ConvertFrom-PemEncoding
{
    [OutputType('byte[]')]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Label,
        [Parameter(Mandatory=$true)]
        [string] $PemData
    )

    $base64 = $PemData `
        -Replace "`n","" -Replace "`r","" `
        -Replace "-----BEGIN $Label-----", "" `
        -Replace "-----END $Label-----", ""

    return [Convert]::FromBase64String($base64)
}

function Split-PemChain
{
    [OutputType('System.String[]')]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Label,
        [Parameter(Mandatory=$true)]
        [string] $PemData
    )

    [string[]] $PemChain = @()
    $PemData | Select-String  -Pattern "(?smi)^-{2,}BEGIN $Label-{2,}.*?-{2,}END $Label-{2,}" `
        -Allmatches | ForEach-Object { $_.Matches } | ForEach-Object { $PemChain += $_.Value }

    return $PemChain
}

function Get-IsPemCertificateAuthority
{
    [OutputType('bool')]
    param(
        [Parameter(Mandatory=$true)]
        [string] $PemData
    )

    $der = ConvertFrom-PemEncoding -Label 'CERTIFICATE' -PemData:$PemData
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]] $der)

    foreach ($extension in $cert.Extensions) {
        if ($extension.Oid.Value -eq "2.5.29.19") {
            $extension = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] $extension
            return $extension.CertificateAuthority
        }
    }

    return $false
}

function Get-PemCertificate
{
    param(
        [string] $CertificateFile,
        [string] $PrivateKeyFile,
        [string] $Password
    )

    if (($CertificateFile -match ".pfx") -or ($CertificateFile -match ".p12")) {
        $AsByteStream = if ($PSEdition -eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
        $CertificateData = Get-Content -Path $CertificateFile -Raw @AsByteStream
        $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $collection.Import($CertificateData, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    
        [string[]] $PemChain = @()
        $PrivateKey = $null
    
        foreach ($cert in $collection) {
            if ($cert.HasPrivateKey) {
                $PrivateKey = ConvertFrom-RsaPrivateKey -Rsa $cert.PrivateKey
            }
            $PemCert = ConvertTo-PemEncoding -Label 'CERTIFICATE' -RawData $cert.RawData    
            $PemChain += $PemCert
        }
    
        if ($PemChain.Count -eq 0) {
            throw "Empty certificate chain!"
        }

        if (Get-IsPemCertificateAuthority -PemData $PemChain[0]) {
            [array]::Reverse($PemChain)
        }
    
        $Certificate = $PemChain -Join "`n"

        return [PSCustomObject]@{
            Certificate = $Certificate
            PrivateKey = $PrivateKey
        }
    } else {
        $PemData = Get-Content -Path $CertificateFile -Raw
        [string[]] $PemChain = Split-PemChain -Label 'CERTIFICATE' -PemData $PemData

        if ($PemChain.Count -eq 0) {
            throw "Empty certificate chain!"
        }
        
        if (Get-IsPemCertificateAuthority -PemData $PemChain[0]) {
            [array]::Reverse($PemChain)
        }

        $Certificate = $PemChain -Join "`n"
        $PrivateKey = Get-Content -Path $PrivateKeyFile -Raw

        return [PSCustomObject]@{
            Certificate = $Certificate
            PrivateKey = $PrivateKey
        }
    }
}
