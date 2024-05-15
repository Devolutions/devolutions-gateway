
function ConvertTo-RsaPrivateKey
{
    [OutputType('System.Security.Cryptography.RSA')]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Pem
    )

    if ($PSEdition -eq 'Core') {
        $Rsa = [System.Security.Cryptography.RSA]::Create()
        $Rsa.ImportFromPem($Pem)
        $Rsa
    } else {
        throw "ConvertTo-RsaPrivateKey unsupported in Windows PowerShell"
    }
}

function ConvertFrom-RsaPrivateKey
{
    [OutputType('System.String')]
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.RSA] $Rsa
    )

    if ($PSEdition -eq 'Core') {
        $bytes = $Rsa.ExportRSAPrivateKey()
        ConvertTo-PemEncoding -Label "PRIVATE KEY" -RawData $bytes
    } else {
        throw "ConvertFrom-RsaPrivateKey unsupported in Windows PowerShell"
    }
}

function New-RsaKeyPair
{
    param(
        [int] $KeySize = 2048
    )

    $bits = [System.UIntPtr]::op_Explicit($KeySize)
    $Rsa = [Devolutions.Picky.PrivateKey]::GenerateRsa($bits)
    $PublicKey = $Rsa.ToPublicKey().ToPem().ToRepr()
    $PrivateKey = $Rsa.ToPem().ToRepr()

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

function Get-CertificateIssuerName
{
    [OutputType('string')]
    param(
        [Parameter(Mandatory=$true)]
        [string] $PemData
    )

    $der = ConvertFrom-PemEncoding -Label 'CERTIFICATE' -PemData:$PemData
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]] $der)

    return $cert.IssuerName.Name
}

function Get-CertificateSubjectName
{
    [OutputType('string')]
    param(
        [Parameter(Mandatory=$true)]
        [string] $PemData
    )

    $der = ConvertFrom-PemEncoding -Label 'CERTIFICATE' -PemData:$PemData
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]] $der)

    return $cert.SubjectName.Name
}

function Expand-PfxCertificate
{
    param (
        [Parameter(Mandatory = $true)]
        [Devolutions.Picky.Pfx] $Pfx
    )

    $Certificates = New-Object 'System.Collections.Generic.List[Devolutions.Picky.Cert]'

    $safeBagIterator = $Pfx.SafeBags()
    $safeBag = $safeBagIterator.Next()

    while ($null -ne $safeBag) {
        switch ($safeBag.Kind) {
            'Certificate' {
                $Certificates.Add($safeBag.Certificate)
            }
            'PrivateKey' {
                $PrivateKey = $safeBag.PrivateKey
            }
        }

        $safeBag.Dispose()
        $safeBag = $safeBagIterator.Next()
    }

    return [PSCustomObject]@{
        Certificates = $Certificates
        PrivateKey = $PrivateKey
    }
}

function Get-PemCertificate
{
    param(
        [string] $CertificateFile,
        [string] $PrivateKeyFile,
        [string] $Password
    )

    [string[]] $PemChain = @()
    $PrivateKey = $null

    if (($CertificateFile -match ".pfx") -or ($CertificateFile -match ".p12")) {
        $AsByteStream = if ($PSEdition -eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
        $PfxBytes = Get-Content -Path $CertificateFile -Raw @AsByteStream

        $parsingParams = [Devolutions.Picky.Pkcs12ParsingParams]::New.Invoke(@())
        $parsingParams.SkipDecryptionErrors = $true
        $parsingParams.SkipMacValidation = $true

        $pkcs12CryptoContext = if ($null -eq $password) {
            [Devolutions.Picky.Pkcs12CryptoContext]::NoPassword()
        } else {
            [Devolutions.Picky.Pkcs12CryptoContext]::WithPassword($password)
        }

        $pfx = [Devolutions.Picky.Pfx]::FromDer($PfxBytes, $pkcs12CryptoContext, $parsingParams)
        $expanded = Expand-PfxCertificate -Pfx $pfx

        $sb = New-Object System.Text.StringBuilder
        foreach ($cert in $expanded.Certificates) {
            $pem = $cert.ToPem()
            [void]$sb.AppendLine($pem.ToRepr())
        }
        $PemData = $sb.ToString()

        if ($null -ne $expanded.PrivateKey) {
            $PrivateKey = $expanded.PrivateKey.ToPem().ToRepr()
        }
    } else {
        
        try {
            $PemData = [System.IO.File]::ReadAllBytes($CertificateFile)
            # Try to parse the file as if it was a DER binary file.
            $Cert = [Devolutions.Picky.Cert]::FromDer($PemData);
            $PemData = $Cert.ToPem().ToRepr();
        } catch {
            # Assume we have a PEM.
            $PemData = Get-Content -Path $CertificateFile -Encoding UTF8 -Raw
        }

        try {
            $PrivateKey = [System.IO.File]::ReadAllBytes($PrivateKeyFile)
            # Try to parse the file as if it was a DER binary file.
            $PrivateKey = [Devolutions.Picky.PrivateKey]::FromPkcs8($PrivateKey);
            $PrivateKey = $PrivateKey.ToPem().ToRepr();
        } catch {
            # Assume we have a PEM.
            $PrivateKey = Get-Content -Path $PrivateKeyFile -Encoding UTF8 -Raw
        }
    }

    $PemChain = Split-PemChain -Label 'CERTIFICATE' -PemData $PemData

    if ($PemChain.Count -eq 0) {
        throw "Empty certificate chain!"
    }

    $PemChain | ForEach-Object -Begin {
        $Certs = @{}
    } -Process {
        $Key = Get-CertificateSubjectName -PemData $_
        $Certs.Add($Key, $_)
    } -End {
        $Certs
    }

    $LeafCert = $PemChain | Where-Object { -Not ( Get-IsPemCertificateAuthority -PemData $_ )}

    [string[]] $SortedPemChain = @()

    if ($null -eq $LeafCert) {
        # Do not apply any transformation to the provided chain if no leaf certificate is found
        $SortedPemChain = $PemChain
    } else {
        # Otherwise, sort the chain: start by the leaf and then issued to issuer in order

        $SortedPemChain += $LeafCert
        $IssuerName = Get-CertificateIssuerName -PemData $LeafCert
        $SubjectName = Get-CertificateSubjectName -PemData $LeafCert

        While ($Certs.ContainsKey($IssuerName) -And ($IssuerName -Ne $SubjectName)) {
            $NextCert = $Certs[$IssuerName]
            $SortedPemChain += $NextCert
            $IssuerName = Get-CertificateIssuerName -PemData $NextCert
            $SubjectName = Get-CertificateSubjectName -PemData $NextCert
        }
    }

    $Certificate = $SortedPemChain -Join "`n"

    return [PSCustomObject]@{
        Certificate = $Certificate
        PrivateKey = $PrivateKey
    }
}
