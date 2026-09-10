# Repository & Release Notes

Maintainer reference for the `powertrain-burp-extension` repo. Not needed by users
installing the extension — see [INSTALL.md](INSTALL.md) for that.

## Canonical filenames

| File | Purpose |
|------|---------|
| `powertrain_burp_extension.py` | The extension. This is the only extension filename — no spaces, no `cve_analyzer` variant. |
| `README.md` | User-facing documentation |
| `INSTALL.md` | Installation guide |
| `DESIGN.md` | Scoring architecture: the base / environmental split |
| `CONTRIBUTING.md`, `LICENSE` | Contribution terms and license |
| `main-interface.png`, `cve-analysis.png`, `context-menu.png` | README screenshots |

If you find `Oxytis Powertrain Analyzer.py` or `powertrain_cve_analyzer.py`
referenced anywhere, they are stale names for the same file — fix the reference to
`powertrain_burp_extension.py`.

## Cutting a release

1. Land the change on `main`; make sure the extension loads in Burp with no errors
   in the Output/Errors tabs.
2. Update the README changelog with the new version and date.
3. Tag the release (`vMAJOR.MINOR`) and write release notes from the changelog.
4. Attach `powertrain_burp_extension.py` as a release asset, plus any doc changed
   in the release (e.g. `DESIGN.md` for v1.5).
5. Keep one tag per file state: don't attach a file containing a later release's
   changes to an earlier tag.

## Release history

- **v1.5** — scoring model documentation (base/environmental split) and Oxytis
  Risk relabelled as a contextual prioritization score, not a CVSS score.
- **v1.4** — finding evidence redacted by default; Evidence-sent modes and payload
  preview.
- **v1.3** — no-CVE finding assessment; deterministic CVSS 4.0 via FIRST `cvss`.
  (The README changelog originally mislabelled this v1.1.0.)
- **v1.2.1** — CVSS severity display fix.
- **v1.0.0** — initial release: CVE analysis, SOO, HEXAD, context menu.

## Repository settings

- Topics: `burp-suite`, `security`, `cve-analysis`, `penetration-testing`,
  `vulnerability-assessment`
- Issues enabled; Wiki optional
- Description: "Professional Burp Suite extension integrating Oxytis Powertrain
  vulnerability intelligence (CVE analysis + no-CVE finding assessment)."
