Describe "Test-Assessment-70006" {
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

        $classPath = Join-Path $srcRoot "classes/ZtTest.ps1"
        if (-not ("ZtTest" -as [type])) {
            . $classPath
        }

        $sut = Join-Path $srcRoot "tests/Test-Assessment.70006.ps1"
        . $sut

        $script:outputFile = Join-Path $here "../TestResults/Report-Test-Assessment.70006.md"
        $outputDir = Split-Path $script:outputFile
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir | Out-Null
        }
        "# Test Results for 70006`n" | Set-Content $script:outputFile
    }

    BeforeEach {
        Mock Write-PSFMessage {}
        Mock Write-ZtProgress {}
        Mock Get-SafeMarkdown { param($Text) return $Text }
    }

    Context "When a repository has an unhealthy exposed-secret finding" {
        It "Should fail and list the repository" {
            Mock Invoke-ZtAzureResourceGraphRequest {
                return @(
                    [PSCustomObject]@{ subscriptionId='s1'; resourceName='contoso/api'; resourceId='/r/1'; displayName='Code repositories should have secret scanning findings resolved'; state='Unhealthy'; severity='High'; portal='portal.azure.com/x' }
                )
            }

            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                $script:capturedResult = $Result
                "## Scenario: unhealthy secret`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $Status -eq $false }
            $script:capturedResult | Should -Match "contoso/api"
        }
    }

    Context "When secret findings are all healthy" {
        It "Should pass" {
            Mock Invoke-ZtAzureResourceGraphRequest {
                return @(
                    [PSCustomObject]@{ subscriptionId='s1'; resourceName='contoso/web'; resourceId='/r/2'; displayName='Code repositories should have secret scanning findings resolved'; state='Healthy'; severity='High'; portal='' }
                )
            }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: healthy`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $Status -eq $true }
        }
    }

    Context "When there are no DevOps secret assessments" {
        It "Should skip as NotApplicable" {
            Mock Invoke-ZtAzureResourceGraphRequest { return @() }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: none`n`n$SkippedBecause`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $SkippedBecause -eq 'NotApplicable' }
        }
    }

    Context "When the account lacks Azure access" {
        It "Should skip with NoAzureAccess on a 403" {
            Mock Invoke-ZtAzureResourceGraphRequest { throw "Azure REST request failed with status 403: Forbidden" }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: no access`n`n$SkippedBecause`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $SkippedBecause -eq 'NoAzureAccess' }
        }
    }

    Context "When Resource Graph fails for another reason" {
        It "Should skip with NotSupported" {
            Mock Invoke-ZtAzureResourceGraphRequest { throw "Some unexpected error" }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus, $SkippedBecause)
                "## Scenario: arg failure`n`n$SkippedBecause`n" | Add-Content $script:outputFile
            }

            Test-Assessment-70006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter { $SkippedBecause -eq 'NotSupported' }
        }
    }
}
