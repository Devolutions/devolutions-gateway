function ConvertTo-DGatewayMsiProperty {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z][A-Z0-9_.]*$')]
        [string] $Name,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value.Contains([string][char]0)) {
        throw 'MSI property values cannot contain a null character'
    }

    # Windows Installer escapes literal quotation marks by doubling them.
    '{0}="{1}"' -f $Name, $Value.Replace('"', '""')
}
