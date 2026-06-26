Workload Identity Federation (WIF) lets an external workload — a GitHub Actions workflow, an Azure DevOps pipeline, or another OIDC-capable system — exchange a short-lived identity-provider token for a Microsoft Entra access token. No client secret or certificate is stored in the pipeline, which removes the most commonly leaked credential in CI/CD. This check flags application registrations that still authenticate with long-lived client secrets or certificates and have no federated identity credentials configured, identifying the workloads that should migrate to keyless authentication.

Long-lived application secrets and certificates are a frequent source of compromise: they get committed to source control, copied into pipeline variables, shared between environments, and left to expire unnoticed. An application that holds a client secret but no federated credential is a candidate to move to Workload Identity Federation, eliminating the standing credential entirely. This check maps to DevSecOps workshop task DS_030.

**Source:** [Workload identity federation overview](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)

**Remediation action**

- [Configure a federated identity credential on an app registration](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust)
- [Use GitHub Actions to authenticate to Azure with federated credentials](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-config-app-trust-github)
- [Set up workload identity federation for Azure DevOps service connections](https://learn.microsoft.com/azure/devops/pipelines/release/configure-workload-identity)

<!--- Results --->
%TestResult%
