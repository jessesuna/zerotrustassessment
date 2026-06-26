Microsoft Defender for Cloud's DevOps security scans connected GitHub, Azure DevOps, and GitLab repositories for exposed secrets — credentials, tokens, and keys committed to source. When a secret is found, Defender raises a security assessment against the repository. This check verifies that none of those exposed-secret assessments remain unhealthy, meaning the secrets have been rotated and the findings remediated. It maps to DevSecOps workshop tasks DS_013 (enable secret scanning and push protection) and DS_065 (triage and remediate existing secret scanning alerts).

An exposed secret in source control is one of the highest-impact supply chain risks: anyone with repository access — or anyone who obtains a leaked clone or fork — can use the credential to access cloud resources, pipelines, or data. Detecting the secret is only half the control; the finding must be driven to resolution by rotating the credential and removing it from history. Unresolved exposed-secret findings represent live, usable credentials sitting in your repositories.

This is a focused DevSecOps view of a single control. The broader Microsoft Defender for Cloud Recommendations check surfaces every recommendation across all environments; this check answers one question with a direct pass or fail.

**Source:** [DevOps security in Microsoft Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-devops-introduction)

**Remediation action**

- [Remediate secrets found in code](https://learn.microsoft.com/azure/defender-for-cloud/detect-exposed-secrets)
- [Enable secret scanning for your DevOps environment](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-devops-introduction)

<!--- Results --->
%TestResult%
