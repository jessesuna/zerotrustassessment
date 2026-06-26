Describe "Test-Assessment-70001" {
    BeforeAll {
        $here = $PSScriptRoot
        $srcRoot = Join-Path $here "../../src/powershell"

        if (-not (Get-Command Write-PSFMessage -ErrorAction SilentlyContinue)) {
            function Write-PSFMessage {}
        }
        # Stub module-internal helpers so Mock can override them when run standalone
        if (-not (Get-Command Write-ZtProgress -ErrorAction SilentlyContinue)) {
            function Write-ZtProgress {}
        }
        if (-not (Get-Command Get-SafeMarkdown -ErrorAction SilentlyContinue)) {
            function Get-SafeMarkdown { param($Text) $Text }
        }
        if (-not (Get-Command Invoke-ZtAzureResourceGraphRequest -ErrorAction SilentlyContinue)) {
            function Invoke-ZtAzureResourceGraphRequest { param($Query) @() }
        }
        if (-not (Get-Command Add-ZtTestResultDetail -ErrorAction SilentlyContinue)) {
            function Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $GraphObjects, $GraphObjectType,
                    $CustomStatus, $SkippedBecause, $UserImpact, $Risk, $ImplementationCost,
                    $AppliesTo, $Tag, $NotConnectedService, $Pillar, $Category, $Description)
            }
        }

        # Load the ZtTest attribute class
        $classPath = Join-Path $srcRoot "classes/ZtTest.ps1"
        if (-not ("ZtTest" -as [type])) {
            . $classPath
        }

        # Load the system under test
        $sut = Join-Path $srcRoot "tests/Test-Assessment.70001.ps1"
        . $sut

        $script:outputFile = Join-Path $here "../TestResults/Report-Test-Assessment.70001.md"
        $outputDir = Split-Path $script:outputFile
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir | Out-Null
        }
        "# Test Results for 70001`n" | Set-Content $script:outputFile
    }

    BeforeEach {
        Mock Write-PSFMessage {}
        Mock Write-ZtProgress {}
        Mock Get-SafeMarkdown { param($Text) return $Text }
    }

    Context "When at least one DevOps connector exists and is provisioned" {
        It "Should pass" {
            Mock Invoke-ZtAzureResourceGraphRequest {
                return @(
                    [PSCustomObject]@{
                        id                = '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Security/securityConnectors/gh1'
                        name              = 'gh1'
                        subscriptionId    = 's1'
                        environmentName   = 'GitHub'
                        hierarchyIdentifier = 'contoso-org'
                        provisioningState = 'Succeeded'
                    }
                )
            }

            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                $script:capturedResult = $Result
                "## Scenario: One provisioned connector`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70001

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $true
            }
            $script:capturedResult | Should -Match "GitHub"
        }
    }

    Context "When no DevOps connectors exist" {
        It "Should fail and recommend onboarding" {
            Mock Invoke-ZtAzureResourceGraphRequest { return @() }

            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                $script:capturedResult = $Result
                "## Scenario: No connectors`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70001

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false
            }
            $script:capturedResult | Should -Match "No GitHub, Azure DevOps, or GitLab"
        }
    }

    Context "When a connector is not fully provisioned" {
        It "Should return Investigate" {
            Mock Invoke-ZtAzureResourceGraphRequest {
                return @(
                    [PSCustomObject]@{
                        id                = '/subscriptions/s1/.../ado1'
                        name              = 'ado1'
                        subscriptionId    = 's1'
                        environmentName   = 'AzureDevOps'
                        hierarchyIdentifier = 'contoso'
                        provisioningState = 'Pending'
                    }
                )
            }

            $script:capturedCustom = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                $script:capturedCustom = $CustomStatus
                "## Scenario: Not provisioned`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70001

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $CustomStatus -eq 'Investigate'
            }
        }
    }

    Context "When the account lacks Azure access" {
        It "Should skip with NoAzureAccess on a 403" {
            Mock Invoke-ZtAzureResourceGraphRequest { throw "Azure REST request failed with status 403: Forbidden" }

            $script:capturedSkip = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                $script:capturedSkip = $SkippedBecause
                "## Scenario: No Azure access`n`n$SkippedBecause`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70001

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $SkippedBecause -eq 'NoAzureAccess'
            }
        }
    }

    Context "When Resource Graph fails for another reason" {
        It "Should skip with NotSupported" {
            Mock Invoke-ZtAzureResourceGraphRequest { throw "Some unexpected error" }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: ARG failure`n`n$SkippedBecause`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70001

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $SkippedBecause -eq 'NotSupported'
            }
        }
    }
}
