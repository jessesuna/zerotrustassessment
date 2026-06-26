<#
.SYNOPSIS
    Validates that workload identities use federated identity credentials (keyless)
    rather than long-lived client secrets or certificates.

.DESCRIPTION
    This test inspects every application registration and flags those that authenticate
    with long-lived client secrets or certificates but have no federated identity
    credentials (FIC) configured. Such applications are prime candidates to migrate to
    Workload Identity Federation, which removes standing secrets from CI/CD pipelines and
    other workloads.

    Federated identity credentials let GitHub Actions, Azure DevOps, and other workloads
    exchange a short-lived OIDC token for a Microsoft Entra access token, so no secret is
    stored in the pipeline. Applications that still rely on client secrets or certificates
    keep a long-lived credential that can be leaked, phished, or left to expire unnoticed.

    Requires that the Application export collects the federatedIdentityCredentials
    navigation property (see RelatedPropertyNames in export-tenant.config.psd1).

    Maps to DevSecOps workshop task DS_030 "Configure Workload Identity Federation for keyless CI/CD".

.NOTES
    Test ID: 70040
    Category: DevSecOps Pipeline Identity
    Required data: Application table (with federatedIdentityCredentials)
#>

function Test-Assessment-70040 {

    [ZtTest(
        Category = 'DevSecOps Pipeline Identity',
        ImplementationCost = 'Medium',
        Service = ('Graph'),
        CompatibleLicense = ('Entra-ID-Free'),
        Pillar = 'DevSecOps',
        RiskLevel = 'High',
        SfiPillar = 'Protect identities and secrets',
        TenantType = ('Workforce'),
        TestId = 70040,
        Title = 'Workload identities use federated credentials instead of long-lived secrets',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param(
        $Database
    )

    #region Data Collection

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Evaluating Workload Identity Federation adoption for application registrations'
    Write-ZtProgress -Activity $activity -Status 'Querying application credentials'

    # Pull credential collections for every application; evaluate in PowerShell so the
    # logic is robust to how DuckDB materializes the JSON arrays.
    $sql = @"
SELECT id, appId, displayName, passwordCredentials, keyCredentials, federatedIdentityCredentials
FROM main.Application
"@

    $applications = @()
    try {
        $applications = @(Invoke-DatabaseQuery -Database $Database -Sql $sql)
    }
    catch {
        Write-PSFMessage "Application credential query failed: $($_.Exception.Message)" -Tag Test -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NotSupported
        return
    }

    # Helper: treat null / empty / '[]' / empty array as "no entries"
    function Test-HasEntries {
        param($Value)
        if ($null -eq $Value) { return $false }
        if ($Value -is [string]) { return ($Value.Trim() -ne '' -and $Value.Trim() -ne '[]') }
        if ($Value -is [System.Collections.IEnumerable]) { return (@($Value).Count -gt 0) }
        return $true
    }

    $migrationCandidates = @()
    foreach ($app in $applications) {
        $hasSecret = (Test-HasEntries $app.passwordCredentials) -or (Test-HasEntries $app.keyCredentials)
        $hasFic    = Test-HasEntries $app.federatedIdentityCredentials
        if ($hasSecret -and -not $hasFic) {
            $migrationCandidates += [PSCustomObject]@{
                Id          = $app.id
                AppId       = $app.appId
                DisplayName = $app.displayName
            }
        }
    }

    #endregion Data Collection

    #region Assessment Logic

    $passed = $migrationCandidates.Count -eq 0
    $customStatus = $null

    if ($passed) {
        $testResultMarkdown = "✅ No application registrations rely solely on long-lived secrets or certificates; workloads can use federated identity credentials.`n`n%TestResult%"
    }
    else {
        $customStatus = 'Investigate'
        $testResultMarkdown = "⚠️ One or more application registrations use long-lived secrets or certificates with no federated identity credentials. Evaluate migrating these workloads to Workload Identity Federation.`n`n%TestResult%"
    }

    #endregion Assessment Logic

    #region Report Generation

    $mdInfo = ''
    if ($migrationCandidates.Count -gt 0) {
        $formatTemplate = @'


## Application registrations to migrate to Workload Identity Federation

| Application | App ID |
| :---------- | :----- |
{0}
'@
        $tableRows         = ''
        $maxItemsToDisplay = 10
        $displayResults    = @($migrationCandidates | Sort-Object DisplayName)
        $hasMoreItems      = $false
        if ($displayResults.Count -gt $maxItemsToDisplay) {
            $displayResults = @($displayResults | Select-Object -First $maxItemsToDisplay)
            $hasMoreItems   = $true
        }

        foreach ($app in $displayResults) {
            $portalLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/{0}' -f $app.AppId
            $name = if ([string]::IsNullOrWhiteSpace($app.DisplayName)) { '(unnamed)' } else { Get-SafeMarkdown $app.DisplayName }
            $tableRows += "| [$name]($portalLink) | $($app.AppId) |`n"
        }

        if ($hasMoreItems) {
            $remainingCount = $migrationCandidates.Count - $maxItemsToDisplay
            $tableRows += "`n... and $remainingCount more.`n"
        }

        $mdInfo = $formatTemplate -f $tableRows
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo

    #endregion Report Generation

    $params = @{
        TestId = '70040'
        Title  = 'Workload identities use federated credentials instead of long-lived secrets'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }

    Add-ZtTestResultDetail @params
}
