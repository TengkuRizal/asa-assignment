# Security Findings

## Scope and evidence

This report separates manual code-review findings and the recorded npm audit
baseline from scans that have not yet run in GitHub Actions. Severity labels below
are qualitative assessments for this application, not CVSS scores.

| Source and scan type | Finding and severity rationale | Business impact | Origin | Status and evidence |
|---|---|---|---|---|
| Manual review | Direct scan reads lacked owner scoping. **High**: an authenticated user who can supply another scan ID could read that user's vulnerability data. | Could disclose affected assets, vulnerabilities, and remediation details to another tenant. | Starter code | Remediated with scan-ID and owner filtering; unauthorized reads return 404. Ownership regression tests are in `tests/test_api.py`. |
| Manual review | Search did not consistently scope results to the authenticated owner. **High**: cross-user results expose vulnerability records beyond the caller's tenant. | Could disclose other users' scan results and remediation status. | Starter code | Remediated with owner-scoped search. Owner-isolation tests are in `tests/test_api.py`. |
| Manual review | Search SQL interpolated the search term. **High**: untrusted query input could alter the intended database query. | Could expose scan data beyond the intended search; actual database impact depends on the deployed database and permissions. | Starter code | Remediated with bound SQL parameters. Regression tests are in `tests/test_api.py`. |
| Manual review during feature design | Share-link creation must verify that the requester owns the scan. **High**: otherwise an authenticated user with another scan ID could create a public link. | Could expose another user's scan to anyone holding the link for up to 24 hours. | New shared-report feature | Owner check is implemented; non-owner creation is covered by sharing tests in `tests/test_api.py`. |
| `npm audit` baseline; SCA | The recorded baseline reported 11 dependency vulnerabilities: 1 critical, 5 high, 2 moderate, 3 low. Severity follows npm audit's classification; package reachability and exploitability have not been assessed here. | A vulnerable notification-service dependency could affect the service if the vulnerable code path is reachable. Review the baseline JSON before assigning package-specific impact. | Starter notification service | Open pending package-level review and approval of any dependency changes. Evidence: `reports/baseline/sca.npm-audit.json`. |

The latest recorded Python suite result was 16 passed with 4 warnings. This is test
evidence, not a substitute for security-scan results.

## Security scans still pending

No successful GitHub Actions run or uploaded scan artifacts have been verified.
Do not report findings or clean results from these configured jobs until their
raw reports are reviewed:

- SAST: `reports/sast.semgrep.json`
- SCA: `reports/sca.trivy.json`
- Container: `reports/container.trivy.json`
- IaC: `reports/iac.checkov.json`
