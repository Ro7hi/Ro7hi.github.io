# Dependency review for a chatbot stack

**Question.** Which changes between two audit snapshots justify closing a finding?

**Evidence.** The inputs are two constructed, pip-audit-shaped JSON reports with four fictional packages in each. The comparison normalizes package names and checks for a match between advisory IDs and supplied aliases within a package.

| Package | What changed | Decision |
| --- | --- | --- |
| demo-parser | LAB-02-A reappears as its known alias LAB-02-B. The package is still at 2.0. | Keep the finding open. |
| demo-bridge | The first report has LAB-03. The second skips the package. | Record a coverage gap and obtain a complete inventory. |
| demo-session | After a recorded change from 1.0 to 1.1, the second snapshot lists the package with zero findings. | Mark LAB-01 as no longer reported. Verify the change and its behavior before closure. |
| demo-utils | LAB-04 appears in the second report at the same package version. | Triage it as newly reported. Advisory data can change independently of code. |

**Real component check.** A separate local execution tested a developer-authored Jinja template with three ordinary messages. Plain text, an ampersand and literal angle brackets produced the expected HTML on Jinja2 3.1.6. Exact inputs, outputs and the observed version are in `evidence/renderer.json`. Pallets' release notes link this version to the fix for GHSA-cpwx-vrp4-4pq7. These functional checks cover presentation behavior. They do not attempt to reproduce the advisory.

**Decision.** Preserve alias history, record coverage gaps, and pair a package change with an application check. A lower total alone cannot establish a fix.

**Scope.** The dependency snapshots are fictitious. The Jinja test ran on the local reference component. The original Flask chatbot source, environment and production requirements were unavailable for this review. No remediation is claimed for that application.

**Replay.** Use `python3 run_portfolio.py` for the offline case. For the optional real component check, use a Python environment with Jinja2 installed and run `python3 02_chatbot_dependency_review/check_renderer.py`.

[PyPA audit format and behavior](https://github.com/pypa/pip-audit) · [Jinja 3.1.6 release notes](https://jinja.palletsprojects.com/en/stable/changes/#version-3-1-6) · [Reviewed advisory and version range](https://github.com/advisories/GHSA-cpwx-vrp4-4pq7)
