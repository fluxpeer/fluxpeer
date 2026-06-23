# Security policy

## Reporting a vulnerability

Email **security@fluxpeer.org** (PGP key available on request). Please do **not** open a
public issue for a security problem. We aim to acknowledge within 72 hours and to agree a
fix and coordinated-disclosure timeline with you. Good-faith research is welcome; please
avoid privacy violations, data destruction, and service disruption while testing.

A machine-readable contact is published at `/.well-known/security.txt` on our sites.

## Scope

- This repository: the fluxpeer **engine, CLI, SDK**, **control/relay/node** servers, and
  the **GUI clients** (`app/`, `desktop/`).
- The managed service (**fluxpeer.com**) and its infrastructure — same contact.

## What we commit to

- We do not log, inspect, or store the contents of your traffic — and because the client
  and data plane are open source, that claim is **auditable**, not just asserted. See the
  Transparency page on our site.
- We publish independent security-audit reports as they are completed.
- Supported versions: the latest release on `main`. Older releases receive security fixes
  on a best-effort basis.
