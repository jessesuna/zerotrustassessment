The Microsoft Defender for Cloud DevOps security connector is the foundation of DevOps posture management. It links your GitHub, Azure DevOps, or GitLab organizations to Defender for Cloud so that code scanning, secret scanning, dependency, and infrastructure-as-code findings — along with code-to-cloud traceability and attack path analysis — are surfaced centrally for security teams. Without at least one connector, none of these DevOps security signals exist for your repositories and pipelines.

When no DevOps environment is connected, security teams have no visibility into exposed secrets, vulnerable dependencies, IaC misconfigurations, or code vulnerabilities in the software supply chain, and cannot trace a deployed resource back to the pipeline and repository that produced it. This check verifies that at least one GitHub, Azure DevOps, or GitLab connector exists and is provisioned successfully. It maps to DevSecOps workshop task DS_050.

**Source:** [Overview - DevOps security in Microsoft Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-devops-introduction)

**Remediation action**

- [Connect your GitHub environment to Microsoft Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-github)
- [Connect your Azure DevOps environment to Microsoft Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-devops)
- [Connect your GitLab environment to Microsoft Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-gitlab)

<!--- Results --->
%TestResult%
