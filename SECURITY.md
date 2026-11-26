# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue. Use the
**Report a vulnerability** button on this repository's
[Security tab](https://github.com/sujayamindev/secret-share-tool/security/advisories/new).

Include what you found, how to reproduce it, and what an attacker gains. You
should get a reply within a week. This is a one-person project, so there is no
bounty.

## Scope

In scope: this repository's code and the live instance at
https://secrets.sujaya.dev.

The [threat model](README.md#threat-model) lists what the design does and does
not protect against. A report that the server could serve malicious JavaScript,
or that an unrestricted link opens for anyone who has it, describes a stated
limit, not a vulnerability. A way around one of the stated protections is
exactly what this policy is for.

Please do not run load tests or automated scanners against the live instance,
and do not try to read secrets that are not yours.
