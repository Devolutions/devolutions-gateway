BeforeAll {
    . $PSScriptRoot/linux-changelog.ps1
}

Describe 'Format-EntryLine' {
    It 'Removes markdown links enclosed in parantheses' {
        $Input = '([foo](http://foo.example))'
        $Expected = ''
        $Actual = Format-EntryLine -Line $Input
        $Actual | Should -Be $Expected
    }

    It 'Removes links' {
        $Input = '[foo](http://foo.example)'
        $Expected = ''
        $Actual = Format-EntryLine -Line $Input
        $Actual | Should -Be $Expected
    }

    It 'Removes bold formatting' {
        $Input = '**foo**'
        $Expected = 'foo'
        $Actual = Format-EntryLine -Line $Input
        $Actual | Should -Be $Expected
    }

    It 'Removes italics (underscore)' {
        $Input = '_foo_'
        $Expected = 'foo'
        $Actual = Format-EntryLine -Line $Input
        $Actual | Should -Be $Expected
    }

    It 'Removes italics (asterisk)' {
        $Input = '*foo*'
        $Expected = 'foo'
        $Actual = Format-EntryLine -Line $Input
        $Actual | Should -Be $Expected
    }

    It 'Removes monospace' {
        $Input = '`foo`'
        $Expected = 'foo'
        $Actual = Format-EntryLine -Line $Input
        $Actual | Should -Be $Expected
    }

    It 'Removes blockquote marker' {
        $Input = '> foo'
        $Expected = 'foo'
        $Actual = Format-EntryLine -Line $Input
        $Actual | Should -Be $Expected
    }
}

Describe 'Format-DebEntry' {
    It 'Formats a CHANGELOG.md entry into an Debian format' {
        $Version = '0.1.0'
        $Date = '2025-01-01'
        $Packager = 'Maurice'
        $Email = 'maurice@foo.example'
        $PackageName = 'my-package'
        $Distro = 'focal'
        $Body = "  * Bug fixes`n"  # body already formatted

        $Expected = @"
my-package (0.1.0-1) focal; urgency=medium

  * Bug fixes

 -- Maurice <maurice@foo.example>  Wed, 01 Jan 2025 00:00:00 +0000
"@

        $Actual = Format-DebEntry -Version $Version -Date $Date -Packager $Packager -Email $Email -PackageName $PackageName -Distro $Distro -Body $Body
        $Actual | Should -Be $Expected
    }
}

Describe 'Format-RpmUpstreamEntry' {
    It 'Formats a CHANGELOG.md entry into an upstream RPM entry' {
        $Version = '0.1.0'
        $Date = '2025-01-01'
        $Packager = 'Maurice'
        $Email = 'maurice@foo.example'
        $Body = "* Bug fixes`n"  # body already formatted

        $Expected = @"
0.1.0 (2025-01-01) Maurice <maurice@foo.example>

* Bug fixes
"@

        $Actual = Format-RpmUpstreamEntry -Version $Version -Date $Date -Packager  $Packager -Email $Email -Body $Body 
        $Actual | Should -Be $Expected
    }
}

Describe 'Format-RpmPackagingEntry' {
    It 'Formats a CHANGELOG.md entry into a packaging RPM entry' {
        $Version = '0.1.0'
        $Date = '2025-01-01'
        $Packager = 'Maurice'
        $Email = 'maurice@foo.example'
        $Body = "- Removed dependency`n"  # body already formatted

        $Expected = @"
* Wed Jan 01 2025 Maurice <maurice@foo.example> - 0.1.0-1
- Removed dependency
"@

        $Actual = Format-RpmPackagingEntry -Version $Version -Date $Date -Packager  $Packager -Email $Email -Body $Body 
        $Actual | Should -Be $Expected
    }
}


Describe 'New-UpstreamChangelog' {
    BeforeEach {
        $tmpfile = New-TemporaryFile
        Set-Content -Path $tmpfile.FullName -Value @"
## 0.2.0 (2025-01-01)

### Features
- abc
  - abcabc

### Bug Fixes
- def

## 0.1.0 (2024-01-01)
- ghi
"@
    }

    AfterEach {
        # clean up
        Remove-Item -Path $tmpfile.FullName -Force
    }

    It 'Generates a Debian upstream changelog' {
        $Date = '2025-01-01'
        $Packager = 'Maurice'
        $Email = 'maurice@foo.example'
        $PackageName = 'my-package'
        $Distro = 'focal'

        $Actual = New-Changelog `
            -Format 'Deb' `
            -InputFile $tmpfile.FullName `
            -Packager $Packager `
            -Email $Email `
            -PackageName $PackageName `
            -Distro $Distro

        $Expected = @"
my-package (0.2.0-1) focal; urgency=medium

  * Features
    - abc
      - abcabc
  * Bug Fixes
    - def

 -- Maurice <maurice@foo.example>  Wed, 01 Jan 2025 00:00:00 +0000

my-package (0.1.0-1) focal; urgency=medium

  * ghi

 -- Maurice <maurice@foo.example>  Mon, 01 Jan 2024 00:00:00 +0000
"@

        $Actual | Should -Be $Expected
    }

    It 'Generates an RPM upstream changelog' {
        $Packager = 'Maurice'
        $Email = 'maurice@foo.example'

        $Actual = New-Changelog `
            -Format 'RpmUpstream' `
            -InputFile $tmpfile.FullName `
            -Packager $Packager `
            -Email $Email

        $Expected = @"
0.2.0 (2025-01-01) Maurice <maurice@foo.example>

* abc
  - abcabc
* def

0.1.0 (2024-01-01) Maurice <maurice@foo.example>

* ghi
"@

        $Actual | Should -Be $Expected
    }

    It 'Generates an RPM packaging changelog' {
        $Packager = 'Maurice'
        $Email = 'maurice@foo.example'

        $Actual = New-Changelog `
            -Format 'RpmPackaging' `
            -InputFile $tmpfile.FullName `
            -Packager $Packager `
            -Email $Email

        $Expected = @"
* Wed Jan 01 2025 Maurice <maurice@foo.example> - 0.2.0-1
- abc
- abcabc
- def

* Mon Jan 01 2024 Maurice <maurice@foo.example> - 0.1.0-1
- ghi
"@

        $Actual | Should -Be $Expected
    }
}
