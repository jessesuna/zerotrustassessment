Describe "Test-Assessment-70040" {
    BeforeAll {
        $here = $PSScriptRoot
        $srcRoot = Join-Path $here "../../src/powershell"

        if (-not (Get-Command Write-PSFMessage -ErrorAction SilentlyContinue)) {
            function Write-PSFMessage {}
        }
        if (-not (Get-Command Write-ZtProgress -ErrorAction SilentlyContinue)) {
            function Write-ZtProgress {}
        }
        if (-not (Get-Command Get-SafeMarkdown -ErrorAction SilentlyContinue)) {
            function Get-SafeMarkdown { param($Text) $Text }
        }
        if (-not (Get-Command Invoke-DatabaseQuery -ErrorAction SilentlyContinue)) {
            function Invoke-DatabaseQuery { param($Database, $Sql) @() }
        }
        if (-not (Get-Command Add-ZtTestResultDetail -ErrorAction SilentlyContinue)) {
            function Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $GraphObjects, $GraphObjectType,
                    $CustomStatus, $SkippedBecause, $UserImpact, $Risk, $ImplementationCost,
                    $AppliesTo, $Tag, $NotConnectedService, $Pillar, $Category, $Description)
            }
        }

        $classPath = Join-Path $srcRoot "classes/ZtTest.ps1"
        if (-not ("ZtTest" -as [type])) {
            . $classPath
        }

        $sut = Join-Path $srcRoot "tests/Test-Assessment.70040.ps1"
        . $sut

        $script:outputFile = Join-Path $here "../TestResults/Report-Test-Assessment.70040.md"
        $outputDir = Split-Path $script:outputFile
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir | Out-Null
        }
        "# Test Results for 70040`n" | Set-Content $script:outputFile
    }

    BeforeEach {
        Mock Write-PSFMessage {}
        Mock Write-ZtProgress {}
        Mock Get-SafeMarkdown { param($Text) return $Text }
    }

    Context "When an app uses secrets but has no federated credentials" {
        It "Should flag it for migration (Investigate)" {
            Mock Invoke-DatabaseQuery {
                return @(
                    [PSCustomObject]@{
                        id = 'a1'; appId = '11111111-1111-1111-1111-111111111111'; displayName = 'pipeline-sp'
                        passwordCredentials = @(@{ keyId = 'k1' })
                        keyCredentials = @()
                        federatedIdentityCredentials = @()
                    }
                )
            }

            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                $script:capturedResult = $Result
                "## Scenario: secret, no FIC`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70040 -Database 'x'

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $CustomStatus -eq 'Investigate'
            }
            $script:capturedResult | Should -Match "pipeline-sp"
        }
    }

    Context "When an app uses secrets AND has federated credentials" {
        It "Should pass" {
            Mock Invoke-DatabaseQuery {
                return @(
                    [PSCustomObject]@{
                        id = 'a2'; appId = '22222222-2222-2222-2222-222222222222'; displayName = 'modern-sp'
                        passwordCredentials = @(@{ keyId = 'k1' })
                        keyCredentials = @()
                        federatedIdentityCredentials = @(@{ name = 'gh-main' })
                    }
                )
            }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: secret + FIC`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70040 -Database 'x'

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $Status -eq $true }
        }
    }

    Context "When an app uses only federated credentials" {
        It "Should pass" {
            Mock Invoke-DatabaseQuery {
                return @(
                    [PSCustomObject]@{
                        id = 'a3'; appId = '33333333-3333-3333-3333-333333333333'; displayName = 'keyless-sp'
                        passwordCredentials = @()
                        keyCredentials = @()
                        federatedIdentityCredentials = @(@{ name = 'ado-prod' })
                    }
                )
            }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: FIC only`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70040 -Database 'x'

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $Status -eq $true }
        }
    }

    Context "When there are no applications" {
        It "Should pass" {
            Mock Invoke-DatabaseQuery { return @() }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: no apps`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70040 -Database 'x'

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $Status -eq $true }
        }
    }

    Context "When the database query fails" {
        It "Should skip with NotSupported" {
            Mock Invoke-DatabaseQuery { throw "DuckDB error" }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: query failure`n`n$SkippedBecause`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70040 -Database 'x'

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $SkippedBecause -eq 'NotSupported' }
        }
    }
}
