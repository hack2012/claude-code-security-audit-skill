# CVSS v4.0 Scoring Guide

Use this guide for every audit finding, including dashboard findings. This skill provides a scoring workflow, not a bundled calculation engine.

## Applicability and Evidence

1. Decide whether the finding describes a concrete exploitable vulnerability. Record the affected system, attacker capabilities, prerequisites, and demonstrated impact.
2. For an applicable vulnerability, use **CVSS-B** by default and justify every Base metric from code, configuration, dashboard observations, or a matching advisory. Static evidence can support scoring; exploitation is not required.
3. If required evidence or a calculator is unavailable, report **Unscored**, identify the missing metrics or calculation step, and explain what would resolve it. Do not invent values, scores, or a complete vector.
4. For a compliance gap or hardening recommendation without an identified vulnerability, report **N/A** with the reason. A dashboard misconfiguration can still be a vulnerability; assess its consequences before selecting N/A.

CVSS severity describes technical vulnerability severity. Remediation priority also considers business impact, exposure, and operational constraints. Confidence describes the strength of evidence. Record priority and confidence separately; neither determines a CVSS metric or score. Existing check priorities are triage hints, not precomputed CVSS ratings.

## Base Metric Evidence

All 11 Base metrics are mandatory. Record the selected value and a specific rationale for each; **X is not a valid unknown value for Base metrics**.

| Metric | Allowed values | Evidence to record |
|--------|----------------|--------------------|
| AV — Attack Vector | N / A / L / P | Where the attacker must be to reach the vulnerable component |
| AC — Attack Complexity | L / H | Conditions requiring evasion or circumvention of security mechanisms |
| AT — Attack Requirements | N / P | Required deployment or execution conditions outside attacker control |
| PR — Privileges Required | N / L / H | Privileges needed before exploitation |
| UI — User Interaction | N / P / A | Whether another user must participate, passively or actively |
| VC — Vulnerable System Confidentiality | H / L / N | Confidentiality loss in the vulnerable system |
| VI — Vulnerable System Integrity | H / L / N | Integrity loss in the vulnerable system |
| VA — Vulnerable System Availability | H / L / N | Availability loss in the vulnerable system |
| SC — Subsequent System Confidentiality | H / L / N | Confidentiality loss beyond the vulnerable system |
| SI — Subsequent System Integrity | H / L / N | Integrity loss beyond the vulnerable system |
| SA — Subsequent System Availability | H / L / N | Availability loss beyond the vulnerable system |

Define the vulnerable and subsequent system boundaries before assigning impact. Do not assume subsequent-system impact merely because a dependency or another service exists. Distinguish AC (circumvention) from AT (prerequisite conditions); do not carry over CVSS v3.x Scope or UI values.

## Calculation and Reporting

Use the [FIRST CVSS v4.0 calculator](https://www.first.org/cvss/calculator/4.0) or a CVSS v4.0 implementation verified against FIRST reference results. Do not calculate a numeric score by hand, estimate it from a title, or convert a v3.x score by relabeling it.

- Enter the justified metrics, then retain the exact vector and calculator result together.
- Record the calculation source (calculator URL, or implementation name/version and verification reference) and assessment date. For an advisory, verify version, affected configuration, vector, and scoring context before reuse; cite the advisory and calculator used.
- Label the metric groups: **CVSS-B** (Base), **CVSS-BT** (Base + Threat), **CVSS-BE** (Base + Environmental), or **CVSS-BTE** (all three). Keep the default CVSS-B result when adding contextual scores, and explain the additional metrics and their evidence/date.
- Threat and Environmental metrics may use Not Defined (X) where permitted. This does not represent missing Base evidence. Supplemental metrics supply context and do **not** change the numeric score.
- Map the returned score to severity: **None: 0.0**, **Low: 0.1–3.9**, **Medium: 4.0–6.9**, **High: 7.0–8.9**, **Critical: 9.0–10.0**.
- Keep Unscored and N/A separate from None (a calculated zero). Include all three states in summaries; never drop incomplete assessments or count them as Low.

## Examples

### Evidence Supports a Base Vector

An unauthenticated network endpoint exposes all records in its own datastore. Evidence establishes no special conditions or user interaction, confidentiality loss only, and no subsequent-system impact:

```text
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

This is an illustrative vector only. Obtain its score and severity from the calculator before using it in a report, and retain the rationale for all metrics. Do not reuse these assumptions for a different endpoint.

### Insufficient Evidence

**CVSS: Unscored** — A suspected injection sink is visible, but the authentication boundary and resulting data access are unknown. PR and VC/VI/VA cannot yet be justified. Inspect the route middleware and query permissions; do not emit a complete vector or numeric score until resolved.

### Non-Vulnerability Recommendation

**CVSS: N/A** — A retention-policy document is missing, with no identified exploitable software weakness. Track the compliance requirement, remediation priority, and evidence confidence separately.

## Review Checklist

- [ ] Every finding has Scored, Unscored, or N/A applicability and rationale.
- [ ] Every scored finding has all 11 Base metric values with evidence and clear system boundaries.
- [ ] The vector uses CVSS:4.0 syntax and matches the calculator input/result.
- [ ] Score, severity, metric-group label, calculation source, and date are recorded.
- [ ] Optional contextual metrics are justified; Supplemental metrics do not alter scores.
- [ ] Unknown Base metrics are not replaced with X or guessed values.
- [ ] Priority and confidence are separate from CVSS severity.
- [ ] Summary counts include None, Unscored, and N/A for code/config and dashboard findings.

## Authoritative References

- [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- [FIRST CVSS v4.0 user guide](https://www.first.org/cvss/v4.0/user-guide)
- [FIRST CVSS v4.0 calculator](https://www.first.org/cvss/calculator/4.0)
