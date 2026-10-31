# Executive Summary

Before this work, a user could potentially view another user's scan records, and
search did not consistently keep results within the user's account. The changes
tighten those access boundaries and add time-limited, optionally password-
protected report sharing. Important security checks and build validations are
still pending, so the service is not ready for production use.

## Security posture before and after

**Before:** The starter service did not consistently restrict scan reads and
search to the owning user. Search also used an unsafe way of building a database
query. The service had no shared-report link feature.

**After:** Direct reads and search enforce ownership, and search uses database
parameters rather than inserting the search text into the query. The new sharing
feature checks scan ownership, stores share tokens hashed, and expires links
after 24 hours. A share may also require a password. A non-root container and
deployment chart have been added, but their build and validation have not yet
been confirmed.

## Top three residual risks

1. **Known dependency vulnerabilities remain.** The recorded npm baseline lists
   one critical and five high findings, plus moderate and low findings. The
   affected package paths and exploitability have not been assessed, and no
   dependency changes have been approved.
2. **Security and deployment checks are incomplete.** The configured scans have
   not produced reviewed reports, and the image build/run and chart validation
   have not been verified. Unknown findings or build issues may remain.
3. **Share passwords travel in a URL query parameter.** This is required by the
   assignment's API contract, but URLs may be retained in browser history or
   logs. Production HTTPS, query-string log redaction, no-store handling, and
   rate limiting have not been verified.

## Recommended next steps

1. Run the complete CI workflow and review the raw SAST, SCA, container, and IaC
   reports.
2. Review the dependency findings and approve specific upgrades; rerun tests and
   scans after changes.
3. Build and run the container with a health check, then lint and render the
   deployment chart. Confirm the external-secret store and ingress settings
   before considering deployment.
4. Before any production use, verify HTTPS, query-string log redaction, cache
   handling, and rate limiting for password-protected share links.

The latest recorded Python test result was 16 passed with 4 warnings. This does
not replace the pending scan, container, and chart validation results. No
production deployment is claimed.
