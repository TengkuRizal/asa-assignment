# Remediation Plan

This plan covers unresolved risks and validation gaps. Do not treat a configured
CI job as a completed control until its run and report have been reviewed.

| Finding or gap | Residual risk | Why it remains open | Effort to remediate | Compensating controls |
|---|---|---|---|---|
| npm audit baseline: 1 critical and 5 high dependency findings, plus 2 moderate and 3 low. | A vulnerable dependency may be exploitable if the affected code path is reachable in the notification service. Reachability has not been established. | Dependency upgrades have not been authorized; no package-specific remediation review is recorded. | Review `reports/baseline/sca.npm-audit.json`, identify fixed versions, update only approved dependencies, run tests, and rescan. | No effective compensating control is verified. The new SCA CI gate is configured but has not completed a verified run. |
| Share password is required as a query parameter by the assignment API contract. | Query parameters can be retained in browser history and may appear in proxy or access logs. | Moving it to a body or header would violate the required endpoint contract. | Low to moderate: configure HTTPS, redact query strings from access logs, add no-store response handling, and consider rate limiting; verify these controls before production use. | The feature also uses a 24-hour link expiry and password verification. Do not claim HTTPS, log redaction, no-store, or rate limiting until verified. |
| Four security scans have not been run and reviewed. | Unknown SAST, current dependency, container, or Helm/IaC findings may remain. | Workflow configuration exists, but no successful run or raw scan artifacts have been verified. | Run CI, download and review all four reports, document package-level and configuration findings, remediate, and rerun. | No scan-result compensating control is verified. Do not claim the pipeline is green. |
| Docker image build/run and Helm lint/render are not yet verified. | The container may fail to build or run; chart templates may fail validation or deployment prerequisites may be missing. | Docker and Helm were unavailable locally; CI has not completed. | Run the image build and container smoke test, then Helm lint and render in CI; address failures before deployment. | No deployment is claimed. Keep the service undeployed until these checks pass. |

## Completed code remediations

- Direct scan reads now enforce owner scoping.
- Search is owner-scoped and uses bound SQL parameters.
- Share creation enforces scan ownership; share tokens are stored hashed and
  expire after 24 hours.

The latest recorded Python test result was 16 passed with 4 warnings. Retain that
as test evidence, not as proof that pending scans, builds, or deployment checks
have passed.
