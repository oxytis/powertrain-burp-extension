# Tally / Powertrain — Scoring Design

## The base / environmental split is deliberate

Tally scores in two layers, and the separation is intentional. Do not collapse them.

### Base layer (frozen, customer-independent)

The CVSS 4.0 base vector is derived from the finding's technical facts alone and
scored deterministically by FIRST's `cvss` library. It measures the severity of
the flaw itself, which does not change from one organization to the next — an
authentication bypass is equally severe at a bank and on a brochure site.

This layer is the product. It is held fixed and consistent on purpose; that
consistency is the whole value of an automated first-pass scorer.

### Environmental layer (per-implementation, not defaulted)

Exposure, control effectiveness, asset criticality, and compliance-driven
Security Requirements (PCI, HIPAA, and similar) belong here. These inputs are
genuinely per-organization and have no universally correct default — which is
exactly why CVSS 4.0 places them in the Environmental group (Modified Base
metrics and CR/IR/AR) and leaves them blank for the assessor to supply. Only the
customer knows their own frameworks and crown jewels; the tool must not guess
them.

The current **Oxytis Risk** number is a lightweight stand-in for this layer: the
CVSS base adjusted by exposure and control effectiveness (plus EPSS likelihood on
the CVE path only, since EPSS is keyed to a published CVE). It is a **contextual
prioritization score, not a CVSS score**, and it is labeled as such in the
output. It is enough to rank findings in an average engagement; it is not a
per-customer environmental assessment.

## The consequence to remember

If an enterprise's PCI scope, regulatory framework, or asset model makes a score
"feel wrong," that is **not a base-layer bug**. The base layer is correctly
refusing to encode one organization's environment into a customer-independent
number. The fix is to supply those factors in the environmental layer for that
engagement — never to tune the base.

Full CVSS 4.0 environmental scoring (real Modified/Requirement vectors instead of
the lightweight adjustment) is the planned path when a specific customer's
framework requires it, and by design it varies per customer.

> **Rule of thumb:** the base layer is the rule-governed part; the environment is
> the judgment part. Determinism belongs in the first and would be false
> precision in the second.

## Why CVSS scoring requires judgment, not just calculation

The CVSS calculation is deterministic once the vector is chosen. The difficult
part is translating a real attack into that vector, and that step has genuine
ambiguity the standard does not resolve. Two illustrations:

**Missing account lockout — where does impact stop?** The missing control itself
changes and denies nothing, but it enables credential compromise. One assessor
scores the direct effect; another attributes the capabilities of the compromised
account (read config, change settings, disrupt the device) to the vulnerability.
Both are defensible. Scoring "a little impact everywhere" because compromise
*might* lead there resolves nothing — it just blends the two stances incoherently.

**Session replay after logoff — impact relative to what?** A captured
authentication hash replays to reactivate a session. Capturing it required the
attacker to already observe the connection. That distinction can push impact
judgments in opposite directions: the case for extra confidentiality impact
weakens (observation was already required), while the case for integrity impact
strengthens (replay grants authority to *act*, not just watch). "Full compromise"
overstates it; "mere session persistence" understates it.

Neither problem is arithmetic. This is why forcing Tally to be perfectly
deterministic above the base layer would be the wrong optimization: where CVSS
gives a clear rule, Tally follows it; where applying that rule requires
architectural or causal judgment, bounded variance is more honest than silently
turning one interpretation into an absolute rule. The goal is not randomness — it
is consistent, explainable, defensible judgment.
