<#
.SYNOPSIS
    Validates that at least one DevOps environment (GitHub, Azure DevOps, or GitLab) is
    connected to Microsoft Defender for Cloud via a security connector.

.DESCRIPTION
    This test enumerates Microsoft.Security/securityConnectors across all accessible Azure
    subscriptions using Azure Resource Graph. A tenant passes when at least one DevOps
    security connector exists and is provisioned successfully. Connectors that are not in a
    'Succeeded' provisioning state are surfaced for investigation.

    The Defender for Cloud DevOps security connector is the prerequisite for every other
    DevOps posture capability (code-to-cloud mapping, attack path analysis, secret/IaC/code
    scanning recommendations and PR annotations). Without a connector, none of those signals
    exist for GitHub or Azure DevOps repositories.

    Maps to DevSecOps workshop task DS_050 "Connect DevOps environments to Defender for Cloud".

.NOTES
    Test ID: 70001
    Category: DevSecOps Posture
    Required APIs: Azure Resource Graph (resources/microsoft.security/securityconnectors)
#>

function Test-Assessment-70001 {

    [ZtTest(
        Category = 'DevSecOps Posture',
        ImplementationCost = 'Medium',
        Service = ('Azure'),
        CompatibleLicense = ('Microsoft_Defender_for_Cloud'),
        Pillar = 'DevSecOps',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 70001,
        Title = 'DevOps environments are connected to Microsoft Defender for Cloud',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Evaluating Microsoft Defender for Cloud DevOps security connectors'

    Write-ZtProgress -Activity $activity -Status 'Querying DevOps security connectors via Resource Graph'

    # Enumerate every Defender for Cloud DevOps connector across all accessible subscriptions.
    $argQuery = @"
resources
| where type =~ 'microsoft.security/securityconnectors'
| extend environmentName = tostring(properties.environmentName)
| where environmentName in~ ('GitHub', 'AzureDevOps', 'GitLab')
| project id,
          name,
          subscriptionId,
          environmentName,
          hierarchyIdentifier = tostring(properties.hierarchyIdentifier),
          provisioningState = tostring(properties.provisioningState)
"@

    $connectors = @()
    try {
        $connectors = @(Invoke-ZtAzureResourceGraphRequest -Query $argQuery)
        Write-PSFMessage "ARG query returned $($connectors.Count) DevOps security connector(s)" -Tag Test -Level VeryVerbose
    }
    catch {
        $httpStatusCode = $null
        if ($_.Exception.Message -match 'with status (\d+):') {
            $httpStatusCode = [int]$Matches[1]
        }

        if ($httpStatusCode -in @(401, 403)) {
            Write-PSFMessage "Access denied querying security connectors: $($_.Exception.Message)" -Tag Test -Level Warning
            Add-ZtTestResultDetail -SkippedBecause NoAzureAccess
            return
        }

        Write-PSFMessage "Azure Resource Graph query failed: $($_.Exception.Message)" -Tag Test -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NotSupported
        return
    }

    #endregion Data Collection

    #region Assessment Logic

    $notProvisioned = @($connectors | Where-Object { $_.provisioningState -ne 'Succeeded' })
    $hasConnector   = $connectors.Count -gt 0
    $passed         = $hasConnector -and ($notProvisioned.Count -eq 0)
    $customStatus   = $null

    if ($hasConnector -and $notProvisioned.Count -gt 0) {
        $customStatus = 'Investigate'
        $testResultMarkdown = "⚠️ One or more DevOps security connectors are not fully provisioned. Review their state in Microsoft Defender for Cloud.`n`n%TestResult%"
    }
    elseif ($passed) {
        $testResultMarkdown = "✅ At least one DevOps environment is connected to Microsoft Defender for Cloud and provisioned successfully.`n`n%TestResult%"
    }
    else {
        $testResultMarkdown = "❌ No GitHub, Azure DevOps, or GitLab environments are connected to Microsoft Defender for Cloud. DevOps posture, code-to-cloud mapping, and security findings are unavailable.`n`n%TestResult%"
    }

    #endregion Assessment Logic

    #region Report Generation

    $portalDevOpsLink = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/DevOpsSecurity'

    $mdInfo = ''
    if ($hasConnector) {
        $formatTemplate = @'


## [DevOps security connectors]({0})

| Environment | Organization / Project | Provisioning state | Status |
| :---------- | :--------------------- | :----------------- | :----- |
{1}
'@
        $tableRows         = ''
        $maxItemsToDisplay = 10
        $statusPriority    = @{ Fail = 0; Pass = 1 }
        $rows = @($connectors | ForEach-Object {
                $rowStatus = if ($_.provisioningState -eq 'Succeeded') { 'Pass' } else { 'Fail' }
                [PSCustomObject]@{
                    Environment       = $_.environmentName
                    Hierarchy         = $_.hierarchyIdentifier
                    ProvisioningState = $_.provisioningState
                    RowStatus         = $rowStatus
                }
            })
        $displayResults = @($rows | Sort-Object { $statusPriority[$_.RowStatus] }, Environment)
        $hasMoreItems   = $false
        if ($displayResults.Count -gt $maxItemsToDisplay) {
            $displayResults = @($displayResults | Select-Object -First $maxItemsToDisplay)
            $hasMoreItems   = $true
        }

        foreach ($row in $displayResults) {
            $statusDisplay = switch ($row.RowStatus) {
                'Pass' { '✅ Provisioned' }
                'Fail' { '⚠️ Investigate' }
            }
            $hierarchy = if ([string]::IsNullOrWhiteSpace($row.Hierarchy)) { '—' } else { Get-SafeMarkdown $row.Hierarchy }
            $tableRows += "| $($row.Environment) | $hierarchy | $($row.ProvisioningState) | $statusDisplay |`n"
        }

        if ($hasMoreItems) {
            $remainingCount = $connectors.Count - $maxItemsToDisplay
            $tableRows += "`n... and $remainingCount more. [View all DevOps connectors in Microsoft Defender for Cloud]($portalDevOpsLink)`n"
        }

        $mdInfo = $formatTemplate -f $portalDevOpsLink, $tableRows
    }
    else {
        $mdInfo = "`n`n[Onboard a DevOps environment in Microsoft Defender for Cloud]($portalDevOpsLink)`n"
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo

    #endregion Report Generation

    $params = @{
        TestId = '70001'
        Title  = 'DevOps environments are connected to Microsoft Defender for Cloud'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }

    Add-ZtTestResultDetail @params
}
