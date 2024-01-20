Import-Module "$PSScriptRoot/../DevolutionsGateway"

Describe 'Devolutions Gateway User Management' {
    InModuleScope DevolutionsGateway {
        BeforeAll {
            $ConfigPath = Join-Path $TestDrive 'Gateway'
            Set-DGatewayConfig -ConfigPath:$ConfigPath -Hostname 'gateway.local'
            $filePath = Join-Path -Path $ConfigPath -ChildPath "users.txt"
            Set-Content -Path $filePath -Value ""
        }

        Context 'User Management' {
            It 'Can add a new user' {
                # Set the user's password
                Set-DGatewayUser -Username "admin" -Password 'password' -ConfigPath $ConfigPath
            
                # Retrieve the user and test if a hash exists
                $user = Get-DGatewayUser -Username "admin" -ConfigPath $ConfigPath
                $user.Hash | Should -Not -BeNullOrEmpty
            }            

            It 'Can edit an existing user' {
                # Get the current hash of the user
                $originalUser = Get-DGatewayUser -Username "admin" -ConfigPath $ConfigPath
                $originalHash = $originalUser.Hash
            
                # Update the user with a new hash
                Set-DGatewayUser -Username "admin" -Password 'newpass' -ConfigPath $ConfigPath
            
                # Retrieve the updated user and hash
                $updatedUser = Get-DGatewayUser -Username "admin" -ConfigPath $ConfigPath
                $updatedHash = $updatedUser.Hash
            
                # The test should pass if the original hash and the updated hash are different
                $updatedHash | Should -Not -Be $originalHash
            }            

            It 'Can remove a user' {
                Remove-DGatewayUser -Username "admin" -ConfigPath $ConfigPath
                $user = Get-DGatewayUser -Username "admin" -ConfigPath $ConfigPath
                $user | Should -Be $null
            }

            It 'Handles non-existing user correctly' {
                $user = Get-DGatewayUser -Username "nonexistent" -ConfigPath $ConfigPath
                $user | Should -Be $null
            }
        }
    }
}
