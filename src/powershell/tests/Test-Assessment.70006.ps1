<#
.SYNOPSIS
    Validates that DevOps repositories connected to Microsoft Defender for Cloud have no
    unresolved exposed-secret findings.

.DESCRIPTION
    This test queries Microsoft Defender for Cloud security assessments (via Azure Resource
    Graph) for secret-scanning findings on DevOps repository resources (GitHub, Azure DevOps,
    GitLab). A tenant passes when no in-scope repository has an unhealthy exposed-secret
    assessment.

    This is a focused, DevSecOps-pillar view of a single high-impact control. The broader
    "Microsoft Defender for Cloud Recommendations" check (50001) surfaces every recommendation
    across all environments; this check answers one DevSecOps question — are exposed secrets in
    source repositories being remediated — with a direct pass/fail.

    Maps to DevSecOps workshop tasks DS_013 (enable secret scanning and push protection) and
    DS_065 (triage and remediate existing secret scanning alerts).

.NOTES
    Test ID: 70006
    Category: DevSecOps Posture
    Required API: Azure Resource Graph - securityresources (microsoft.security/assessments)
#>

function Test-Assessment-70006 {

    [ZtTest(
        Category = 'DevSecOps Posture',
        ImplementationCost = 'Medium',
        Service = ('Azure'),
        CompatibleLicense = ('Microsoft_Defender_for_Cloud'),
        Pillar = 'DevSecOps',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 70006,
        Title = 'DevOps repositories have no unresolved exposed-secret findings',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Evaluating Defender for Cloud exposed-secret findings on DevOps repositories'
    Write-ZtProgress -Activity $activity -Status 'Querying secret-scanning assessments via Resource Graph'

    # Secret-scanning assessments on DevOps repository resources. The DevOps resource provider
    # surfaces these under Microsoft.SecurityDevOps (repositories); match the secret-scanning
    # assessment by display name so the check is resilient to assessment GUID changes.
    $argQuery = @"
securityresources
| where type =~ 'microsoft.security/assessments'
| extend a = parse_json(properties)
| extend rd = parse_json(a.resourceDetails)
| extend resourceType = tostring(rd.ResourceType)
| extend displayName = tostring(a.displayName)
| extend state = tostring(a.status.code)
| where resourceType has 'securitydevops' or resourceType has 'repositories'
| where displayName has 'secret'
| project subscriptionId,
          resourceName = tostring(rd.ResourceName),
          resourceId = tostring(rd.ResourceId),
          displayName,
          state,
          severity = tostring(a.metadata.severity),
          portal = tostring(a.links.azurePortal)
"@

    $assessments = @()
    try {
        $assessments = @(Invoke-ZtAzureResourceGraphRequest -Query $argQuery)
        Write-PSFMessage "ARG query returned $($assessments.Count) DevOps secret assessment(s)" -Tag Test -Level VeryVerbose
    }
    catch {
        $httpStatusCode = $null
        if ($_.Exception.Message -match 'with status (\d+):') { $httpStatusCode = [int]$Matches[1] }
        if ($httpStatusCode -in @(401, 403)) {
            Add-ZtTestResultDetail -SkippedBecause NoAzureAccess
            return
        }
        Write-PSFMessage "Azure Resource Graph query failed: $($_.Exception.Message)" -Tag Test -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NotSupported
        return
    }

    # No DevOps secret assessments means Defender DevOps secret scanning is not producing data
    # (no connector, scanning not enabled, or no repositories) — not applicable rather than a fail.
    if ($assessments.Count -eq 0) {
        Add-ZtTestResultDetail -SkippedBecause NotApplicable -Result 'No DevOps secret-scanning assessments were found. Ensure a DevOps environment is connected to Microsoft Defender for Cloud (see DS_050) and secret scanning is enabled.'
        return
    }

    #endregion Data Collection

    #region Assessment Logic

    $unhealthy = @($assessments | Where-Object { $_.state -eq 'Unhealthy' })
    $passed = $unhealthy.Count -eq 0
    $customStatus = $null

    if ($passed) {
        $testResultMarkdown = "✅ No unresolved exposed-secret findings on DevOps repositories connected to Microsoft Defender for Cloud.`n`n%TestResult%"
    }
    else {
        $testResultMarkdown = "❌ One or more DevOps repositories have unresolved exposed-secret findings. Rotate the exposed secrets and remediate the findings.`n`n%TestResult%"
    }

    #endregion Assessment Logic

    #region Report Generation

    $mdInfo = ''
    if ($unhealthy.Count -gt 0) {
        $formatTemplate = @'


## Repositories with unresolved exposed-secret findings

| Repository | Finding | Severity |
| :--------- | :------ | :------- |
{0}
'@
        $tableRows         = ''
        $maxItemsToDisplay = 10
        $severityPriority  = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
        $displayResults    = @($unhealthy | Sort-Object { $severityPriority[[string]$_.severity] }, resourceName)
        $hasMoreItems      = $false
        if ($displayResults.Count -gt $maxItemsToDisplay) {
            $displayResults = @($displayResults | Select-Object -First $maxItemsToDisplay)
            $hasMoreItems   = $true
        }

        foreach ($row in $displayResults) {
            $repo = if ([string]::IsNullOrWhiteSpace($row.resourceName)) { '(unknown)' } else { Get-SafeMarkdown $row.resourceName }
            if (-not [string]::IsNullOrWhiteSpace($row.portal)) {
                $portal = if ($row.portal -match '^https?://') { $row.portal } else { "https://$($row.portal)" }
                $repo = "[$repo]($portal)"
            }
            $sev = if ([string]::IsNullOrWhiteSpace($row.severity)) { '—' } else { $row.severity }
            $tableRows += "| $repo | $(Get-SafeMarkdown $row.displayName) | $sev |`n"
        }

        if ($hasMoreItems) {
            $remainingCount = $unhealthy.Count - $maxItemsToDisplay
            $tableRows += "`n... and $remainingCount more.`n"
        }

        $mdInfo = $formatTemplate -f $tableRows
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo

    #endregion Report Generation

    $params = @{
        TestId = '70006'
        Title  = 'DevOps repositories have no unresolved exposed-secret findings'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }

    Add-ZtTestResultDetail @params
}
