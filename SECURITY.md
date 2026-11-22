# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately:

* Open a [private GitHub security advisory](https://github.com/0xnullsect0r/enclave-messenger/security/advisories/new) on this repository.
* Or email ari@aricummings.com.

Include what you found, how to reproduce it, and the impact you expect. We
acknowledge reports within 72 hours.

## Disclosure

We follow coordinated disclosure with a 90-day default deadline, shorter if a
fix ships sooner or the issue is being exploited. We credit reporters unless
they ask us not to. A paid bug bounty starts with milestone M10 (public beta).

## Scope

Everything in this repository: the cryptographic core, protocols, servers,
relays and clients. The threat model is in `docs/01-threat-model.md`; known
limits are listed in `docs/00-overview.md`. Reports that a documented limit
exists are welcome but are not vulnerabilities.

## Vulnerability handling

Confirmed issues are triaged within 24 hours, a fix or mitigation plan is set
within 72 hours, and a fixed release ships within 14 days for critical issues.
This follows the EU Cyber Resilience Act timelines.
