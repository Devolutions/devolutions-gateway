
function ConvertTo-PascalCase
{
    [OutputType('System.String')]
    param(
        [Parameter(Position=0)]
        [string] $Value
    )

    # https://devblogs.microsoft.com/oldnewthing/20190909-00/?p=102844
    return [regex]::replace($Value.ToLower(), '(^|_)(.)', { $args[0].Groups[2].Value.ToUpper()})
}

function ConvertTo-SnakeCase
{
    [OutputType('System.String')]
    param(
        [Parameter(Position=0)]
        [string] $Value
    )

    return [regex]::replace($Value, '(?<=.)(?=[A-Z])', '_').ToLower()
}

function ConvertTo-SnakeCaseObject
{
    param(
        [Parameter(Position=0)]
        $Object
    )

    $snake_obj = New-Object -TypeName 'PSObject'

    $Object.PSObject.Properties | ForEach-Object {
        $name = ConvertTo-SnakeCase -Value ($_.Name | Out-String).Trim()

        if ($_.Value -is [string]) {
            $value = ($_.Value | Out-String).Trim()
            if (![string]::IsNullOrEmpty($value)) {
                $snake_obj | Add-Member -MemberType NoteProperty -Name $name -Value $value
            }
        } else {
            $value = $_.Value
            $snake_obj | Add-Member -MemberType NoteProperty -Name $name -Value $value
        }
    }

    return $snake_obj
}

function Remove-DefaultProperties
{
    param(
        [Parameter(Position=0)]
        $DirtyObject,
        [Parameter(Position=1)]
        $DefaultObject
    )

    $CleanObject = New-Object -TypeName 'PSObject'

    $DirtyObject.PSObject.Properties | ForEach-Object {
        $name = $_.Name
        $value = $_.Value

        if (-Not ($DefaultObject.($name) -eq $value)) {
            $CleanObject | Add-Member -MemberType NoteProperty -Name $name -Value $value
        }
    }

    return $CleanObject
}
